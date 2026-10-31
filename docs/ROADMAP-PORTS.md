# 移植规格书 — 从 7 个参考实现抄什么、怎么抄、怎么验收

本文件是 `qa/redblue/run-redblue.ps1` 的配套：每移植一项，跑一次红蓝评测器，看分数变化。
范围：`C:\Users\Administrator\Desktop\MC\混淆器\` 下 7 个参考库。
**排除**（按要求）：云端授权 / 在线吊销 / 指纹绑定；以及比我们弱的 BytecodeVM、native-obfuscator。

---

## 0. 红蓝评测口径（验收基线）

`qa/redblue/run-redblue.ps1 -Jar <产物> [-Dll <dll>]`，8 行红队检查（7 组攻击，「还原厂商包名」与「常量池算法名」同属明文符号组），蓝队得分 = 通过行数 / 总行数。

| 检查 | 现状（demo / balanced，2026-10-31） | ZKM 27 |
|---|---|---|
| 还原厂商包名 | FAIL 3/735 | PASS 0/16 |
| 常量池算法名 | FAIL 1 类 | FAIL 1 类 |
| CFR 完全结构化率 | **PASS 42%**（块重排前 58%；maximum 8%） | 未按新口径重测 |
| 反射 dump 类载荷 | PASS | PASS |
| 导出表重建映射 | PASS（未用原生） | PASS |
| 工具指纹 | PASS | PASS |
| VM 固定魔数 | PASS | PASS |
| OTP 状态可复用 | PASS 36 入口点 / 17 类（关闭 classEncryption 时；整包加密则记 N/A） | FAIL 0（无该层） |
| **总分** | **6/8（balanced + classEncryption 关 + otp 开）** | 未按新口径重测 |

CFR 行口径（3.2.2 起）：一个类只有被 CFR **完全结构化**（输出里没有 `Unable to fully structure code`）才算「被反编译成功」，判据 `< 50%`。旧口径数的是输出里的 `public class` 字样，量到的是类修饰符（内部类/抽象类没有 `public`），会把「CFR 只能给 goto 兜底」的类误判成成功。

OTP 行判据：产物里能找到一个同时声明 `public static long next()` 与 `public static int carrier()` 的 OTP 状态类，且方法入口前 40 条指令内出现 `invokestatic <otp>.carrier:()I` 的调用点 ≥ 5、覆盖 ≥ 2 个类 → PASS；找不到状态类且产物可读（`otp.enabled=false`）→ FAIL；整包被 `classEncryption` 加密、静态不可观测 → `N/A` 并从分母剔除。

> 行数 7 → 8（3.2.2 加 OTP 行）。上表 ZKM 列是 7 行口径的历史值，未重测。

任何移植项的验收 = 至少一项 FAIL→PASS，或该指标显著下降，且产物仍能运行。

---

## P0-1 字段不透明谓词（ZKM）

**来源**：`ZelixKlassMaster-27/demo/src/main/java/com/zelix/klassmaster/obfuscator/rename/../OpaquePredicateField.java`（307 行）
关键点：谓词值是**字段**（`nonZeroValue`），通过 `createBranchIfSet(label)` 生成 `GETFIELD + IFNE`，可选 getter/setter 访问器；配合 `MethodFlowAnalyzer`（162 KB）做方法级块重排。

**我们的现状（3.2.2：P0-1a + P0-1b + 尾部方法级重排全部落地）**
1. `expected` 已是**双字段相等**：`emitFieldGuard` 发 `GETSTATIC f0; GETSTATIC f1; IF_ICMPEQ real`，两个字段在 `<clinit>` 里用**不同形状**的算术（含 `System.nanoTime()` 派生）算出同值，反编译器读初值也折不掉。
2. 守卫从 prelude 一次 → **每个基本块入口一次**（受 `flow.maxBlocks`/指令预算约束），失败分支仍是 `junk()`。
3. **方法级块重排（尾部）**：新增 `FlowObfuscationPass.reorderBlocks`（`flow.reorder` 选项，`balanced`/`maximum`/`aggressive` 开启）——把若干独立基本块从方法体里抬出来、按乱序追加到方法末尾，把每条 fall-through 边补成显式 `GOTO`，并在块的原位置留一条指向新位置的 `GOTO`。安全边界：只搬「入口操作数栈为空、不落在任何异常范围/边界上、不含 monitor 指令」的块，结果一律过 `MethodGate` 校验（不过就整方法回滚）。

**验收（已达成，2026-10-31 实测）**
- 度量口径改为「CFR 是否**完全结构化**」（输出里没有 `Unable to fully structure code`），因为原口径数的是 `public class` 字样，量到的是类修饰符而不是混淆强度（内部类/抽象类本来就没有 `public`）。
- `demo` + `balanced`（classEncryption 关）：完全结构化率 **58% → 42%**（块重排前 → 后），达到 <50% 目标。
- `demo` + `maximum`（classEncryption 关）：完全结构化率 **8%**（2/25 个带守卫的类）。
- 实测规模：balanced 206 个方法里重排 886 个块（0 次校验跳过）；maximum 848 个方法里重排 6784 个块。
- 产物仍能运行：三档 `java -jar` 均 `OK`，maximum 过 `-Xverify:all`，SnakeGame maximum 能开窗口。
- `FlowTest` 新增 `testFlowReordering`：对重排后的字节码跑完整行为矩阵（switch/循环/try-catch/边界值），260401 checks 全绿。

**落点**：`FlowObfuscationPass`（`emitFieldGuard`、块级守卫、`reorderBlocks`/`labelFor`）、`Presets`（`flow.reorder`）、`tests/FlowTest.testFlowReordering`、`qa/p01/cfr-quality.ps1`（结构化率探针）。
**剩余**：无（P0-1 全部完成）。若要进一步压低结构化率，下一步是**不可约控制流**（从循环外额外进入循环体的克隆块），不在原规格内。
**风险**：块重排只改物理布局，不改 CFG —— 能压结构化率（42%/8%）但压不到 0；不可约 CFG 才是下一档，属于新课题。

---

## P0-2 K-OTP 一次性程序（kboxObfuscator-3.0.3）

**来源**：`kboxObfuscator-3.0.3`，README「保护层」表：`K-OTP | 原生种子驱动的一次性程序，每次调用后重随机 | enableOtp`

**现状（3.2.2：P0-2-a + P0-2-b 已落地）**
1. `core/runtime/UmbraOtp`（运行时模板，`RuntimeSupport.ensureOtp` → `TemplateInjector` 注入成随机名类，和其它 helper 一样剥调试信息）：静态 `long state`，`next()`/`carrier()`/`peek()`/`bit()`/`nativeBound()`；xorshift64 加奇数常量排除零状态固定点；推进在单个 synchronized 块里（并发调用不会拿到同一个值）。
2. `FlowObfuscationPass` 在**每个被保护方法入口**用 `carrier()` 当载体（替代 `System.nanoTime()` 采样），并用 `carrier & 1` 选 junk 分支：junk 栈中性、不碰局部变量，两条路径语义等价，但执行的指令序列每次不同；`carrier` 低 bit 严格交替，所以"下一次调用走另一条路"是确定性的，不是概率性的。
3. 选项 `otp.enabled`（默认 false；`balanced`/`maximum`/`aggressive` 开启；`light` 保持关闭以维持最小产物承诺）。
4. 实测：demo `balanced` 206 个方法、`maximum` 820 个方法接上入口推进；红蓝新增行 PASS（36 入口点 / 17 类），同一产物 `--set otp.enabled=false` 后该行 FAIL（4/8 → 5/8）。
5. **原生推进（P0-2-b）**：`GuardCodeGenerator` 在给了 OTP 类名时额外生成 `umbra_native_otp`（xorshift64 ^ `g_secret`，零值兜底），并在 `JNI_OnLoad` 里用第二次 `RegisterNatives` 把它绑成 OTP 类的 `nativeNext(J)J`；类名与 guard 类名同样按 secret 异或编码，**不进** magic 定位的函数表（那表驱动 prologue 哈希，扩容会废掉所有旧 guard 的期望 prologue）。`NativeGuardPass` 在 `otp.enabled && otp.native && flow.enabled()` 时把 OTP 类名传下去并记 `otp.native` 统计。`UmbraOtp` 侧最多重试 8 次绑定，之后固定走 Java 路径，异常不外泄（这段代码在每个被保护方法的入口里）。实测（`qa\otp-3.2.2\probe\NativeOtpProbe.java`）：guard 加载后 `nativeBound()==1`，即状态推进真的在 DLL 里算。

**未完成（P0-2-c 字符串槽位）**
- `UmbraStringCipher` 的调用点是 `d(parts, siteSeed, siteId, engine)`，engine 与密文在构建期绑定，单次调用换不了密钥；要做到"每次调用解密路径不同"，需要每个站点存两份不同引擎的密文、由 OTP bit 选择，工作量集中在 `StringEncryptionPass`（45 KB）。

**落点**（已落地）：`core/runtime/UmbraOtp`、`RuntimeSupport.ensureOtp`、`DefaultRuntimeSupport`、`FlowObfuscationPass`、`Presets`、`NativeGuardPass`、`jni/guard/GuardCodeGenerator`、`src/test/java/io/umbra/tests/OtpTest.java`、`NativeDynamicTest`（4 条 C 源断言）。
**验收**（已达成）：同一方法二次调用内部状态不同 —— `OtpTest` 17 checks（状态推进、低 bit 交替、并发不重复、注入类在产物里、入口调用点 ≥5、入口 `carrier & 1` 分支、产物可运行）；`NativeDynamicTest` 122 checks（含 OTP native 绑定契约）；红蓝新增行 PASS。
**剩余工时**：字符串槽位 2~3 天。
**风险**：状态推进与线程安全（已用单锁解决）；高频纯函数方法的开销（未做方法白名单，当前只受 `flowObfuscation.maxInstructions` 预算约束）；OTP 类在 classEncryption 产物里可能 `FindClass` 不到，此时原生绑定静默退回 Java 路径（`nativeBound()==0`），不是错误但强度低。

---

## P0-3 二层方言虚拟化（kbox BFVM / BrainfuckShield）

**来源**：`kboxObfuscator-3.0.3`：`BFVM`（方法体编译为 Brainfuck 方言，由 VM 解释）、`BrainfuckShield`（对 VMP 方法做**第二层**虚拟化：ChaCha20 密文 + 方言解释）。

**我们（3.2.2 现状：第二层已落地，密钥来源未完全按规格）**
- 第二层本来就有：`UmbraCantrip` 把 VM2 的 payload 块编成 Cantrip 方言程序（`~value;.`），由注入的方言解释器重建整数。
- **本次补上的**：① **每构建不同的 opcode 表** —— 方言文本先按 seed 派生的 128 项置换表替换，再 ChaCha20（20 轮，计数器从 1）加密，Base64 存储；产物里不再有可直接读的 `~value;.` 程序。② 解释器只暴露 `runSealed(String[], int)`（解码+执行）与 `decode`（自检用），方言语义留在 `run` 里。③ 构建期 sealer 与运行期解释器**是同一个类**（`UmbraCantrip.seal` / `runSealed`），两边不可能漂移。④ 选项 `cantrip.seal`（默认 true），关掉即回到老的单层明文方言路径。
- 实测（`--preset light --set cantrip.enabled=true --set vm2.enabled=true`）：102 个 holder **全部**调 `runSealed`，产物 `java -jar` 打印 OK；balanced 产物（classEncryption 开）同样 OK 且过 `-Xverify:all`；`CantripTest` 14 checks（含封签往返、错密钥不还原）、`Vm3Test` 131、`VmTest` 548 全绿。

**未按规格做的部分（要写清楚）**
- 规格第 2 条要求"密钥来自 `nested` 外程序的运行期状态"。本次用的是**构建期 seed 派生密钥**：payload 必须在 `<clinit>` 里解出来，而那时外层程序的运行期状态还不存在；真按运行期状态派生需要外程序先把密钥算出来再传给 payload（等于给 payload 加一条运行期密钥通道），属下一档工作。
- "不同栈模型"没做：仍是 Cantrip 的单带模型，只换了 opcode 表与加密层。

**落点**：`UmbraCantrip`（`seal`/`decode`/`runSealed` + ChaCha20 + 置换表）、`VirtualizationPass.createCantripChunk`、`Presets`（无新预设项，沿用 `cantrip.enabled`）、`tests/CantripTest`。
**验收**：`固定魔数定位 VM 载荷` 仍 PASS（载荷仍是 VM2 格式，未改魔数）；产物可运行；解释器不暴露语义。
**风险**：解释器体积与启动开销翻倍；必须保留 `vm2.dispatchShardSize` 分片，否则再撞 64KB。

---

## P0-4 调用图隐藏（kbox）

**来源**：`kboxObfuscator-3.0.3` 控制流层：「调用图隐藏」。

**我们**：只有 `referenceObfuscation`（静态调用→indy）。缺的是**调用图噪声**：伪造边、切碎直接调用、把调用点散到不同 holder。

**移植方案**
1. 在现有 indy 化基础上，为每个调用点插入 **k 选 1 的调用目标**（运行期用字段谓词选真目标，其余是 decoy 方法）。
2. 生成 `callgraph` 噪声方法（真实但不被调用），使静态可达图失真。

**落点**：`ReferenceObfuscationPass` + `FlowObfuscationPass`。
**验收**：新增检查「静态调用图可达方法数 ≫ 真实方法数」。
**工时**：3~4 天。
**风险**：indy 站点数量爆炸 → 必须复用同一 bootstrap 并做上限（`referenceObfuscation.maxPerClass`）。

---

## P1-5 原生壳（kbox kboXShield）

**来源**：`kboxObfuscator-3.0.3`：`kboXShield | PE 壳：全节加密、合成导入表、函数级虚拟化、指令变形 | nativeShell, protectNativeLibs`

**关键差异**：这是 **PE 可执行壳**，保护的是 Windows 原生程序；我们保护 `.jar` + 生成的 DLL。
**可移植的部分（只这三项）**：
1. **DLL 段加密**：生成的 C 代码里把字面量池/字符串表放进 `.data` 并运行期解密（我们已加密字面量池，可扩展为“节级”）。
2. **合成导入表**：我们 DLL 导入表目前可被 `objdump` 读出（`GetModuleHandle`/`GetProcAddress` 等），可改成运行期 `LoadLibrary` + 哈希解析。
3. **函数级虚拟化**：把热点 C 函数编译成我们自己的 C-VM（大工程）。

**我们（3.2.2 现状：两项已落地，函数级虚拟化明确不做）**
1. **合成导入表**：敏感 API（`NtQueryInformationThread`、`NtQuerySystemInformation`、`CheckRemoteDebuggerPresent`、`GetFileAttributesA`、`CreateToolhelp32Snapshot`、`GetModuleHandleA`）改成运行期 `LoadLibraryA` + **FNV 哈希名解析**（PE 里不再出现明文 API 名），其余保持直接导入。实测 `objdump -p` 导入项 **57 → 54**（去掉 4 个、加回 1 个 `LoadLibraryA`），导出表仍只有 `JNI_OnLoad` + `umbra_guard_tick`。
2. **字面量段保护**：guard C 的敏感字面量（`frida`/`gum-`/`jdwp`/`dt_socket`/`attach.dll`/`instrument.dll`/`\\.\pipe\*`/`GetThreadDescription`/`ntdll.dll`/`NtQueryInformation*`/`CheckRemoteDebuggerPresent`/`CreateToolhelp32Snapshot`/`GetFileAttributesA`/`GetTickCount64`）改为构建期封签的字节数组 + 首次使用解码。实测 `strings` 与 `objdump -s -j .rdata` 里这些明文**全部消失**；Linux 分支的 `/proc/self/maps`、`/proc/self/status` 在 Windows 构建里本来就被条件编译掉，改为在**生成的 C 源码**层面断言（`NativeGuardTest`/`NativeDynamicTest` 各一条）。
3. **函数级虚拟化：不做**（周级工程量，且与本次验收无关）。

**落点**：`jni/guard/GuardCodeGenerator`、`GuardDynamicCode`、新 `GuardLiterals`、新 `GuardImports`、`NativeGuardPass`、`NativeGuardTest`/`NativeDynamicTest`。
**验收**：导入表项数下降 ✅；导出表仍只有 `JNI_OnLoad` ✅；明文 API/标记消失 ✅。
**风险**：跨 gcc 版本兼容（TDM-GCC 10.3 实测通过）；`LoadLibraryA` 的解析失败路径必须静默降级（已做：解析失败返回 NULL，调用点判空）。

---

## P1-6 原生内存保护 / 反 dump（PhantomShield）

**来源**：`OpenPhantomShield-main`（393 java + 33 h + 13 cpp），native obfuscation runtime。

**我们（3.2.2 现状：页保护轮换 + 代码段 CRC + 白名单全部落地）**
1. **代码段 CRC 回读**：watchdog tick 对已加载镜像的 `.text` 做 CRC（基线运行期从镜像取，不按构建期字节），检测 inline patch；命中走既有 `umbra_notify(mask)` 通道（新位 `DETECT_CODE_CRC`）。
2. **页保护轮换**：对 guard 关键数据页做 `VirtualProtect` 轮换，稳态值**实测**后存进 `g_page_protect` 并用实测值恢复。根因踩坑：加载器把镜像数据页映射成 `PAGE_WRITECOPY(0x8)`，第一次写入才转 `PAGE_READWRITE(0x4)` —— 早期版本硬编码 `PAGE_READWRITE` 当稳态，于是干净 JVM 上第一次轮换就误判成 dump（就是 `0x4000000` 那轮误报）。修法：启动先写一次解决 COW，再实测稳态；命中后立即自愈（`rotationRepaired=0` 有断言），不会连续误报。
3. **白名单机制**：`execMemoryScan` 在 level 3 会误杀 AWT/Swing；现在命中白名单模块/JVM 自身匿名可执行页就跳过，SnakeGame 在 `level=3` 下存活 8s + 40s 两轮 watchdog deep 均无 stderr。

**落点**：`jni/guard/GuardDynamicCode`、`GuardFeatures`/`GuardOptions`、`UmbraNativeGuard`、`NativeGuardPass`、`NativeDynamicTest`（190 checks）。
**验收**：`反射 dump 类载荷` 在运行期 dump 场景仍 PASS ✅；`level=3` 下 SnakeGame 不再被自家 guard 杀掉 ✅；三个原生套件全绿（NativeTest 110 / NativeGuardTest 95 / NativeDynamicTest 190）。
**风险**：误报面仍然存在（页保护/CRC 都依赖"稳态"假设），所以每次新增检测都要按"干净 JVM 零误报"验收；已知类加密产物里 loader 的 `loadClassPayload` 字面量会让红队「反射 dump」行 FAIL，属类加密层，与本层无关。

---

## 交付顺序与判定

1. **P0-1a → P0-1b**（先拿到反编译率下降的可见收益）
2. **P0-2 K-OTP**（唯一“我们没有”的机制，红队最难受）— **P0-2-a + P0-2-b 已完成（3.2.2）**，P0-2-c（字符串槽位重加密）待做
3. **P0-3 二层虚拟化**（在 VM 上再抬一档）
4. **P0-4 调用图隐藏** — 已完成（跨类假边）
5. **P1-5 / P1-6**（工程量大，收益随平台而定；不阻塞前四项交付）

每一步的完成定义：**红蓝分数上升 + 目标 jar 仍能运行 + 全套测试绿**。
