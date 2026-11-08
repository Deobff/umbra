# Umbra 3.3 加固报告（P0–P9）

> 本轮目标：按 `混淆器弱点与提升方案.md` 把 W1–W13 的致命面堵住，并用同一套攻击脚本做 A/B 验证。
> 判据：语义零破坏（demo 打印 `OK`、`--verify` 通过、25 个测试 runner 全绿）；每条提升有统计数字；对攻侧能复现前后差异。

## 0. 改造前基线（3.2.2 满配，`seed=23303`）

| 指标 | 值 |
|---|---|
| 产物 | 3,260,029 B / 1510 条目 / 1506 类 |
| 加密 | 1502 类 + 2 资源，index v4，masterBinding=sample，level 2 |
| VM2 | 366 方法 / 7964 指令 / 128 indy 桥 / 49 融合 |
| 字符串 | 564 常量；chacha20=138 / aes-ctr=156 / rc4=148 / speck=122；otp 32 站点 |
| MBA | 3457 表达式 + 4378 常量 / 439 方法 |
| 流 | 846 方法 / 4230 谓词 / 12163 junk 块 / 1690 伪异常范围 |
| 扁平化 | 696 方法 / 13443 块 |
| 原生守卫 | DLL 29,184 B |
| 对攻 A2（离线脱壳） | **13,047 ms**，1502/1502 类 + 2/2 资源，摘要全部可重算 |

（完整数字与命令见 `qa/impl/baseline-before.md`）

### 改造中快照（WIP，seed 23303，maximum，`build-lead2/smoke.jar`）

| 指标 | 改造前 | 当前 | 说明 |
|---|---|---|---|
| 产物 | 3,260,029 B | 4,728,985 B（+45%） | 主要来自 VM 覆盖提升与 holder 数量 |
| 类数 | 1506 | 2333（+55%） | 每方法 2 块 holder + 表 holder |
| VM 方法 | 366 | 573 | P4 把每类配额让给真方法体而非转发桩 |
| VM 指令 | 7964 | 15001 | |
| 融合指令 | 49 | 25 | `vm2.fusion.skipRate` 偏高，待 vm 复核 |
| 字符串 | 564 | 374 | 更多字面量随方法进 VM |
| 扁平化 | 696 方法 | 924 方法 | |
| 谓词 | 4230（802 range + 404 hash） | 5445（1941 interval + 842 table + **1991 differential**） | differential = 真·运行期不可判定分支 |
| 运行 | OK | **OK** | maximum 双 seed 仍待集成闸门 |

> 取舍：类数 +55% 是「更多真方法体进 VM」的直接成本。集成时要与 vm 一起把 `vmMaxMethods` / holder 结构调到一个成本可接受的点，并在报告里写明取舍理由。

## 1. 威胁模型修正

本轮侦察纠正了原文档的三处判断，后面的实现按修正后的版本做：

| 原判断 | 实测 |
|---|---|
| W5「357 站点里只有一部分需要动态」 | **0 个需要动态**：满配 `perClassKey=true` 且 engine 不含 xor 时站点根本不发 siteSeed，类密钥是 `ConstantValue` 字面量；dual 两半解出同一明文，Carrier 只选路径不参与密钥 |
| W9「dec 表全程序共用」 | 属实，但根因是 `config.seed()`（默认 `0x5A17`）全程序一份，且 VM 层没有任何构建期秘密 |
| W12「只检测不回写」 | 属实且更糟：C 侧 `(void)action;`，Java 侧 `corrupt` 只是自我失能 |

## 2. 逐项改动

### P0 密钥根搬进 native（W1）

**设计**：per-build 32B root 只存在于 key-bridge DLL 与构建期内存；`master = HMAC(root, label‖comment‖LE32(entryCount))`；构建期通过 `PassContext.NATIVE_KEY_ROOT` 共享给归档加密。

- 原生侧：`core/jni/KeyRootCode.java`（新增）——root 拆 8 个掩码 uint32，运行期重组；`keyRoot(slot,sub,out)` = `HMAC-SHA256(root, label‖LE32(slot)‖LE32(sub))`；自查命中时返回**稳定假 key**；注册失败被容忍（老产物仍可跑）。
- Java 侧：`UmbraNativeLoader.keyRoot(...)` + `deriveKey(slot,sub)`（不可用返回 null，不抛）；`ClassEncryptionPass`/`UmbraClassLoader` 走 native 分支，`@@SEED@@` 不再注入明文。
- 回退：`classEncryption.nativeKey.fallback`（默认 true）→ 无工具链时走旧路径并在 stats 标注；false → 拒绝产出。

**实测证据**

| 检查 | 改造前 `before-max.jar` | 改造后 `nk.jar`（native 绑定档） |
|---|---|---|
| 明文类数 | 4 | 5（多一个 key-bridge loader） |
| 32B base64 seed 常量 | **存在**（`n0luLZmll19Fxjf.class`） | **0 个明文类命中** |
| 日志 binding | `sample(zip-comment+entry-count)` | `native(native-root+comment)` |
| 索引版本 | v4 | **v5**（+buildSerial/serialTag） |
| 端到端 | 运行 OK | `--verify` OK、运行 **OK** |

**集成时踩到并修掉的三个真问题（值得写进交接）**

1. **根派生没对齐**：native 的 `keyRoot(slot,sub,out)` 返回的是 `HMAC(rawRoot, label‖slot‖sub)`，不是 raw root；构建侧直接用了 raw 32B，两边绑到不同字节 → 索引解不开。修法：`UmbraCrypto.nativeKeyRoot(raw,1,0)` 与 `KeyRootCode` 共用同一公式。
2. **javac 常量折叠**：`"...(" + RESOURCE + "): "` 与 `FP0+FP1+FP2` 被编译期折成含 `@@RESOURCE@@` / `@@FP0@@@@FP1@@@@FP2@@` 的**长常量**，精确匹配替换漏掉 → 运行期指纹校验读到占位符 → `ensureLoaded()` 失败 → 静默退出。修法：改子串替换（与 `NativeCodePass.patchLoaderConstants` 一致）。
3. **loader 角色混淆**：`UmbraClassLoader.NATIVE_LOADER`（运行期反射取根的类）与归档装载器是两个类，不是绑错；判定改成四条件（root 发布 + loader 在池 + 其 DLL 资源在池 + ClassNode 声明 `keyRoot(II[B)I`），找不到就 `nativeBound=false`，**绝不产出启动即死的产物**。

**回退与安全**：`classEncryption.nativeKey.fallback=true` 时无工具链仍可产出（stats `classEncryption.nativeKey=0`）；native 模式下 DLL 加载失败是 fail-closed（`-Dumbra.debug` 会给出四类诊断之一）。

### P1 熵不可消去（W3/W4）

**改动**：新增 `core/pass/impl/flow/RuntimeTable.java`（per-class `private static int[] z$t<hex>`，`<clinit>` 里 `xorshift32(nanoTime ^ seed)` 填表，常量以 `TAB[b] = TAB[a] ^ C` 的形式落地）。逐处替换：

- `FlowObfuscationPass` 的 `f0 = n^(n^C)` / `f1 = (n^C)^n`（旧恒等）→ 表项 XOR 关系；
- `ControlFlowFlatteningPass.emitState` 的 `target + (n - n)` → 表值（顺带去掉每条边一次 `nanoTime` 的开销）；
- `MbaPass` 的 `((c^K)^k)^(K^k)` → 表项 XOR（per-method `k` 整个删掉）；
- `ExceptionObfuscationPass` 的 carrier 改用表项作 key。

实测（seed 777）：`cff 11129 runtimeStates`、`mba 2632 runtimeConstants（799 走 fallback）`、`exception 897 table-keyed carriers`、`flow 25 tables / 175 masked`。旧恒等家族在 `src` 上 grep = **0**。

**如实标注的限制**：表项的 patch 里 `C` 仍是 `<clinit>` 字面量。这**提高了折叠代价**（需要数组标量化 + 跨 `<clinit>` 数据流 + PRNG 建模），但**不是信息论意义上的不可消**。报告不把它说成后者。

### P2 不可判定谓词（W6）

**改动**：谓词分两类，不再混用。

- **A 类（false 路会改语义，例如异常 pass 的 dead-throw）**：只用**恒真**形态——区间恒真 `((t & 0x7fffffff) | 8) > (t & 7)`、表关系恒真（两对同值）。这一类的「恒真」必须保证，换成可变分支会真抛异常。
- **B 类（只选 junk 块）**：用**差分分支**——`carrier()` 奇偶选两条栈中性 junk 路。静态上没有固定真值，必须执行且每次不同。

删掉的旧族：`(x*(x+1))&1`、`((x|1)&1)==1`、`x-x==0`、`h^h==0`、`(x>>>30)<=3`、`n^(n^C)`、`target+(n-n)`。

实测（seed 23303，maximum）：**5445 谓词 = 1941 interval + 842 table + 1991 differential**。统计键保留旧别名（`flow.rangePredicates` / `flow.hashPredicates`）以免打断既有断言。

### P3 VM2 per-payload 解码置换（W9）

**改动**：删掉全归档唯一的那张 256 项解码表，改为**按 payload 派生的键控置换**——8 位 Feistel（6 轮，key 由该载荷 `meta` 派生），翻译端与解释器共用同一函数；新 flag `FLAG_KEYED_PERM` 放进 `meta[6]` 空位（**不升 format**，旧 format 3/4 带共享表的读取路径保留）。超级指令捆绑策略也改为 per-program 随机（6 族取 90% 子集、至少 3 族）+ 等价变体（`<`⇔`>` 镜像、`+c`⇔`-(-c)`、交换律操作数互换）+ `skipRate=5%`。

实测（同源对照，只回退这三个文件）：

| 指标 | 旧 | 新 |
|---|---|---|
| 256 项共享表 | 1 张 | **0 张** |
| 融合指令 | 56 | **114（+104%）** |
| 产物 | 2,469,207 B | 2,290,288 B（**−7.2%**） |
| 类数 | 1,491 | 1,134（**−24%**） |

### P4 调用点虚拟化 / 配额修正（W8）

**改动**：

1. **配额归因修正**：旧实现里 `InvokeWrapperPass`/`AntiLlmPass` 先把真方法体挪到 `node.methods` 末尾，VM 按声明顺序取前 16 个 → 配额被 3–5 条的转发桩吃满。改为**候选排序**（真体优先、纯转发最后并受 `vm2.forwarderQuota` 约束），转发桩仍计入配额。
2. **调用目标非常量化**：新超级指令 `SUPER_CALL = 228`，载荷里以 `LDC c1; LDC c2; IXOR; SUPER_CALL op` 的形式出现，目标 id 由运行期值算出。

实测：转发桩「目标常量可见」**100% → 0%**（默认 38/38 隐藏）；VM 方法数 363（≤ 25×16=400，不再超配额）。

未做：把异常处理整体搬进 VM。已在 `qa/impl/vm.md` 记为限制。

### P5 完整性防离线重算（W11）

**改动**：

- per-class digest 改为覆盖 **CP 还原后**的字节（旧实现覆盖 CP 加密后的字节 → 改一个类就能原样重算）；
- digest key 换成 `subKey(root, SLOT_DIGEST, 0)`（无 root 时保持 `master`，兼容 v3/v4）；
- 索引升 **v5**，尾部追加 `buildSerial` + `serialTag = HMAC(digestKey, "d:serial"‖LE32(serial))`；v3/v4/v5 均可读，旧版忽略尾部。

效果：只改类不改索引 → digest 对不上；重算 digest 需要 root 派生的 digest key，而 root 只在 DLL 里 → **重签路径被 P0 挡住**。

### P6 检测升级为破坏（W12）

**改动**（原生侧）：

- 自身代码页保护基线检测（`DETECT_TEXT_RWX`）：`VirtualProtect`/`NtProtectVirtualMemory` 把 `.text` 改成可写的痕迹，按**启动时测量的基线**比对，不硬编码保护常量；
- `PAGE_GUARD` 探针页（`DETECT_GUARD_PROBE`）：私有 `VirtualAlloc` 页（第一版放 `.bss` 会触发 image scan 误报，已修）；
- 代码段哈希升级为 **8 段独立 CRC** + 全段 CRC，段选择改成「真正包含自身函数的那一段」；
- Java 侧 `pairA/pairB` 互相依赖（`DETECT_PAIR`）+ `UmbraGuardLauncher` 在 `check()` 之外**独立调用 `attest()`** + native 一次性 token：换空一个方法体不再够；
- `corrupt` 变成真语义：`nativeInit` 保存 action，`umbra_guard_tick` 仅在 `corrupt` 下返回 1（被翻译成 native 的方法静默返回垃圾），`poison(byte[])/poisoned()` 供归档加载器在命中时先污染再 halt。**默认仍是 throw**。

**攻击方实测（A3）发现的漏洞也已修**：`checkAntiDump()` 里对 `-javaagent` 的检测原来被 `if (!guardConfigured())` 包着——装了 guard 反而让 agent 检测失效。改为**无条件执行**（`guardConfigured()` 只影响处置），`integrity.action=log` 保留逃生门。修后实测：裸 `-javaagent` → 静默 exit 1；`-agentlib:jdwp` → 同样被拒；无 agent 时正常 `OK`。

#### P6.1 原生门控（把业务 payload 的钥匙扣在 DLL 上）

第一版只加了一个 `attest(nonce)` 挑战-应答，**实测无效**：攻击方 `measure.ps1` 显示 `wideDumpClasses = 766`（与无门控完全相同），因为那套攻击只换空检测方法、`attest()` 原样保留，照样算出合法 HMAC。他们还从 dump 的 guard 里抽出了 `GATE_SECRET` 并离线复算 HMAC 6/6 命中。

第二轮改成**两道门**：

1. **check 自证**：`UmbraRuntimeGuard.check()` 每次完整执行后写 `lastCheckDigest = HMAC(gateSecret, "umbra.check.v1"‖LE64(counter)‖LE32(mask))`；`attest(nonce)` 在证据缺失（digest 为 null 或 counter 为 0）时**返回 null**。换空 `check()` → 没有证据 → 门关。
2. **nativeCheck 硬条件**：loader 反射调用注入的 native guard 的 `nativeCheck()`，非 0 → 静默 fail-closed。实测：干净 JVM `0x00000000`，`-javaagent` **`0x00000800`**（deep 模块扫描命中 `instrument.dll`）。这是 Java 侧换空方法体**关不掉**的判据。

构建期五个启用条件（nativeBound / gateSecret / guard 声明 `attest(J)[B` / loader 声明 gate 符号 / 池里有声明 `native int nativeCheck()` 的类），缺一自动退回单钥并记 `classEncryption.nativeGate=0`，绝不产启动即死的产物。索引升 **v6**，guard 与 native guard 标为 gate-free（gate 前可解），业务类 entryKey 追加 `payloadRoot`。

**复测结果（两个 seed 一致）**：

| 准则 | 上一版（单门） | **本轮（双门）** |
|---|---|---|
| untouchedRunsOk | true | **true** |
| guardOnlyStillBlocked | true | **true** |
| wideDumpClasses | 766 / 768 | **12 / 12** |
| patch / patch2 / patch3 | exit 0，全量 dump | **全部 exit 1，只 dump 12 个引导类** |

也就是说：**换空 guard/anti-dump 的方法体这条路已经不通了**——业务类 payload 从没被解密过，dump 出来的只有明文引导类。

**安全边界（照实写，含攻击方已实测的绕过路径）**

攻击方在下一轮把门又撬开了，两条路径都记在 `qa/attack/AFTER-GATE2.md`：

1. **patch4**：把 loader 里那个 Java 包装方法 `nativeGuardMask()` 改成 `return 0` → `nativeCheck()` 根本不会被调用。native 侧再硬，Java 不打这个电话就没用。
2. **patch5**：在 patch4 基础上，把 `check()` 换成只写两个字段（`lastCheckDigest = new byte[]{0}; lastCheckCounter = 1; return;`）→ 证据门只判「非空/非零」，且**证据没有参与 HMAC**，于是被伪造。

实测：patch5 → `exit 0`，dump **766 / 778** 类，ClassCheck 全 OK，与非门控档 758/763 个类逐字节相同。

因此准确表述是：

- **默认攻击集**（换空 5 个检测方法）：766 → **12**，patch 组全部 exit 1。**这条路已经封住。**
- **针对性绕过**（改 loader 包装 + 伪造 2 个字段）：仍能恢复全量 dump。成本从「一键换空」升到「读懂协议 + 定点改 6 处」，但不是不可破。

下一轮的三条修法（攻击方建议，我采纳为方向）：

1. 让 native 的 `gateAttest` **自己再跑一次检测**（不要由 Java 判断 native 的结果），这样 patch4 无效；
2. 证据进 HMAC 且由 **native 下发一次性 token** 作为证据来源，这样 patch5 无法伪造字段；
3. `gateSecret` 不落类文件（DLL 内派生或在 DLL 内做 HMAC）。

#### P6.2 第三轮：判定权搬进 DLL（收尾）

第二轮被 patch4（改 loader 的 Java 包装）+ patch5（伪造 check 证据字段）绕过，dump 恢复到 766/778。根因一句话：**门控的判定权还在 Java 手里**——loader 决定要不要去问 native。

第三轮把判定权搬进 bridge DLL：

- bridge 内新增**只读 Toolhelp32 模块扫描**（`instrument.dll` / `jdwp.dll` / `dt_socket.dll` / `attach.dll`，名字全部密封编译），枚举失败一律视为 0（零误报）；
- `keyRoot(slot=2)` 放行条件 = `gate_open && 扫描干净`；`gateAttest` 校验通过后**先扫描再置 gate_open**；
- 整段在 `UMBRA_GATE_ENABLED` 内，`antiDebug.nativeGate=false` 时 gate/agent 代码完全不编译（bridge 仍 15,872 B vs gate 版 18,944 B）。

**终局复测（两产物一致）**：

| 攻击 | 第二轮 | **第三轮** |
|---|---|---|
| untouchedRunsOk | true | **true** |
| guardOnlyStillBlocked | true | **true** |
| 默认 wide（patch3） | 12 | **12** |
| patch4（改 `nativeGuardMask`） | exit 1 | **exit 1，11 类** |
| **patch5（patch4 + 伪造证据）** | **exit 0，766/778 类** | **exit 1，11/11 类** |
| break5（+ attest→null） | exit 1 | **exit 1** |

patch5 的卡点（攻击方 debug 实测）：`the native library refused the gate attestation` —— Java 侧已经全部伪造成功（mask 0、证据字段任填、HMAC 算对），**是 DLL 内部返回拒绝**。判定权确实搬走了。

**残留（本轮未测，攻击方给了 SKIP 原因）**：

1. **启动后 attach**：gate 在 loader 初始化时评估，之后 attach 的 `instrument.dll` 晚于扫描。需要 `agentmain + retransformClasses` 的 dump agent 才能验证，本轮未实现。
2. **自定义 JVMTI agent**：`-agentpath:foo.dll` 不在固定名单里。建议下一轮改成白名单（系统目录 + JDK 已知模块）或模块签名校验。

**结论口径**：P6 对「内存里换空方法体」这条攻击路径**已封住**（默认 766→12，升级到 patch5 也是 11 类且 exit 1）；「启动后 attach」「自定义 JVMTI agent」两条残留**待补测**，不宣称不可绕过。

### P7 语义欺骗命名（W7）

**改动**：

- 同 depth 的类分组**先用 `context.random()` 打散再分配名字**（此前名字是 `a,b,…,z,A,…` 连续序列，且顺序 = 原类名字母序，直接泄漏结构；同 seed 仍可复现）；
- `renamer.baitNames`（默认 `main,run,start`）保留少数诱饵真名；
- 新增 `DecoyNames`：整包一对一映射到伪库包（`org/slf4j/helpers` 等）+ 定长库尖类名，带 per-build 2 字符随机段、`Class.forName` 冲突检查、避开 `java/javax/jdk/sun`；
- `renamer.strategy`（`flat`/`disguise`/`mixed`）。

### P8 明文区死代码清理（W13）

**已完成**：`UmbraCrypto` 删掉无调用方的 `stringPlain/siteKey/siteNonce/classNonce` 及其域标签字段（删前 grep 过 build 侧，全量 javac 通过）；native 修复了 `UmbraNativeLoader` 的占位符折叠问题（5 个明文类 0 残留）。

**未完成**：通用的注入期 `TemplateTrim`（从 keep 集合做方法级可达性闭包）**没有落地**。原因：`seal`/`masterFromSeed` 等成员同时被 build 侧工具类调用，纯字节码裁剪需要一份完整且可验证的 keep 表；在集成闸门临近时引入它的风险高于收益。已在 §4 残留风险里列为下一轮首要项。

### P9 反编译结构恢复难度

**改动**：在 Flow 层为方法注入「表关系恒假的双入口死循环」——构造上恒假，运行期永不进入，但目标块多了一个循环外入口 → CFG 出现**不可归约边**。

- 第一版 `(carrier & 7) == 9` 被 CFR 的区间分析折叠后整段删除（实测 0 差异），**方案返工**为表关系恒假；
- 每方法 1 条：seed 777/778/779 = **897/897/898** 条 `flow.irreducibleEntries`，0 skips。

CFR 实测（`E:\teeess\work\cfr.jar`，seed 777）：

| 目标 | `Handled impossible loop` | `cfr_ignored_` | 行数 |
|---|---|---|---|
| demo | 0 → **60** | 603 → 811（+34.5%） | +9.4% |
| asm-9.11.jar | 0 → **527** | 5356 → 6971（+30.1%） | +14.0% |

注意：这是实测数字，不是百分比承诺；DecompilerNoisePass 本轮未改。
## 3. 对攻 A/B

`qa/attack/run-all.ps1` 对同一套攻击步骤，分别打旧产物与加固后产物。

### 3.1 基线（旧产物 `demo/demo-max.jar`，攻击方实测）

| # | 攻击 | 结论 | 关键数字 | 机器耗时 |
|---|---|---|---|---|
| A1 | 静态字符串全量还原 | **成功** | 564 站点，静态解出 **563（99.8%）**；292 个双密文站点两半明文 **100% 相同** | 14.2 s |
| A2 | 类加密全量脱壳 | **成功** | **1502/1502** 类，摘要全部校验通过，2 资源全解 | 13.0 s |
| A3 | 内存 dump | **成功**（一次清空守卫即可） | 裸 agent 被抓；清空 guard 两个方法体后 dump **1732** 类，其中 **1129 个与 A2 离线解密逐字节一致** | 8.4 s |
| A4 | VM2 载荷反汇编 | **成功** | **366/366** 载荷，**4,724** 条指令；3–5 条指令的载荷 187 个（51.1%） | 7.6 s |
| A5 | 不透明谓词折叠 | 部分 | 折叠 **82,786** 处，改写 1495 个类（折叠后过不了校验器，属实现问题） | 29.0 s |
| A6 | 完整性重签 | **成功** | 改类 → 重算摘要 → 重封索引 → jar 正常启动 | ~5 s |

攻击方机器可重复耗时合计 **≈77 s**（不含工具开发）。这就量出了旧壳的真实成本：**一分钟量级的全量脱壳，加上一次 guard 打补丁**。

### 3.2 加固后（`build-int/after-*.jar`，**P0 关闭的回退档**）

> 注意：这一档 `classEncryption.nativeKey=false`，用来隔离 P1–P9 的效果；P0 的验证在 §3.4。

| # | 攻击 | 旧产物 | 回退档 | 变化 |
|---|---|---|---|---|
| A1 | 静态字符串还原 | 563/564（99.8%） | **163/374（43.6%）** | 204 个站点卡在运行期派生的 `siteId`，6 个卡 `String[]` 分片 |
| A2 | 类加密脱壳 | 成功 13.0 s | **仍成功**（预期：P0 关闭，seed 仍在） | 索引升 v5，摘要改覆盖 CP 还原后字节 |
| A3 | 内存 dump | 换空 guard 两方法 → 1732 类 | **仍成功**（23303） | 见 §4 残留风险 1；90210 仅因类名逐构建随机而失败 |
| A4 | VM2 反汇编 | 366/366，172 纯转发 | **共享 256 表 0 张**；纯转发 172→42 | P3/P4 生效；攻击方补生成器后仍能解 354/363 |
| A5 | 谓词折叠 | 82,786 处 | **40,894 处（−50.6%）** | `fold-branch` 489→2，`(x\|奇)!=0` 1949→0 |
| A6 | 完整性重签 | 成功 | **仍成功** | v5 的 `serialTag` 用 `digestKey` 派生，P0 关闭时 == masterKey，自洽可重算（见 §4 残留风险 2） |

### 3.3 攻击方顺带发现的真缺陷（已转修）

- **`checkAntiDump()` 的 `-javaagent` 检测被 `if (!guardConfigured())` 跳过**：装了 guard 反而让 agent 检测失效——crypto 已改为**无条件执行**（`guardConfigured()` 只影响处置，`integrity.action=log` 保留逃生门）。
- 类密钥以 `ConstantValue` 字面量躺在常量池（A1 发现，比原文档更狠）：静态工具连 `ldc` 都不用找，直接读字段；本轮的 payload v4 salt 让「一个站点解一次」不再成立。

### 3.4 最终产物（native 绑定档）与终局 A/B

集成闸门最终结果（`build-int2`，**26/26 runner 全绿**）：

| 项 | 结果 |
|---|---|
| 测试 | **26/26 PASS**（含 NativeGuardTest / NativeKeyRootTest / DynamicGuardTest / FlowTest / VmTest） |
| seed 23303 | `Verification: OK`，产物 **OK**，3,688,313 B / 1143 条目 |
| seed 90210 | `Verification: OK`，产物 **OK**，3,715,525 B / 1154 条目 |
| 明文 seed 常量 | **0 个命中**（两产物、5 个明文类全扫；旧产物 1 个） |
| binding | `native(native-root+comment)` + index v5（`FLAG_NATIVE_ROOT`/`BINDING_NATIVE`） |

对最终产物的 A/B（`qa/attack/AFTER-FINAL.md`）：

| 攻击 | 旧产物 | **最终 native 档** | 判读 |
|---|---|---|---|
| A2 类加密脱壳 | 1502/1502，13.0 s | **失败（两产物）**：连「索引 + seed」都定位不到 | **P0 生效** |
| A6 完整性重签 | 成功 | **失败**：没有 masterKey，索引都封不出来 | **P0+P5 生效** |
| A3 换空 `check`/`detected` 两方法 | 成功（1737 类） | **失败**（exit 1） | anti-dump 修复生效 |
| A3 wide 换空 4–5 个方法 | 成功（1732 类） | **成功（764 / 767 个 Umbra 类）** | **P6 仍未封死** |
| A1 字符串静态还原 | 563/564（99.8%） | 163/374（43.6%） | P1/P2 生效；卡在运行期 `siteId` |
| A4 VM2 反汇编 | 366/366 | 载入子集 96.4%（共享表 **0 张**） | P3 生效，但结构仍可逆 |
| A5 谓词折叠 | 82,786 | 38,151（−53.9%） | P1/P2 生效 |

> 口径说明：A2 被挡住后，A1/A4/A5 改为对 A3 运行期 dump 出的 764/767 个类跑，所以是**载入子集**，属收益下界。

## 4. 残留风险（区分「本轮未完成」与「JVM 保护器固有」）

**本轮未完成 / 下一轮首要项**

1. **P6 已从「挡成本」升级为「挡路径」**（本轮收尾完成）：
   - 第一版单门（只做 `attest` 挑战-应答）实测**无效**：wide dump 766/768 与非门控档逐字节相同——攻击者只换空检测方法、保留 `attest()` 就能算出合法 HMAC，且能从 dump 的 guard 抽出 `GATE_SECRET` 离线复算。
   - 第二版双门（`check()` 自证 + `nativeCheck()` 原生硬条件）实测**有效**：`wideDumpClasses 766 → 12`，`patch/patch2/patch3` 全部 exit 1，只 dump 到 12 个明文引导类；`untouchedRunsOk`/`guardOnlyStillBlocked` 保持 true。
   - 仍属「提高成本」而非不可破：拿到 intact guard 的攻击者仍可复现协议；`nativeCheck()` 的 `0x800` 依赖 deep 模块扫描命中 `instrument.dll`（已锁定为门控契约，见 `qa/impl/native.md` §10.1）。
2. **P5 的强度依赖 P0**：`digestKey = subKey(root, SLOT_DIGEST)`，P0 关闭时退化为 `masterKey`，攻击者可自洽重算 `serialTag`（回退档 A6 实测成功）。这是「没有根就没有密钥」的必然，不是 v5 的缺陷。
3. **P8 只做了一半**：源码级删了 `UmbraCrypto` 的死方法；通用注入期 `TemplateTrim` 未落地（keep 表需要完整可验证，临近闸门时风险高于收益）。
4. **字符串层未绑 native 根**：order 70 早于 producer（114），构建期无法确认「DLL 真的存在」，强绑会产「构建成功、运行即死」。需调整 pipeline 顺序（把 string-encryption 移到 105 之后）才能吃满 P0 的收益。
5. **native 只做了 Windows**：Linux/macOS 的 key-bridge 为接口占位（不自查、正常派生），未实现未验证。
6. **A4 结构仍可逆**：per-payload 置换把「一张表解全部」变成「逐个载荷付代价」，攻击方补齐生成器后仍解出 96.4%。这是提高成本，不是不可逆。

**JVM 保护器固有（本轮不消除）**

7. 有代码执行能力的攻击者最终一定能拿到运行期明文；P0/P6 做的是提高成本。
8. **启动器可在用户态读子进程内存**（攻防赛实测）：正常 `java -jar` 时 System(4)/csrss/conhost/父启动器都持有 `ALL_ACCESS` 句柄——这是 `CreateProcess` 的语义，不是缺陷。本层（句柄检测 + 100ms 看门狗 + 模块路径 + 内存卫生）能把「全量 722 类」压到「≤100 可用非 JDK」，但**无法清零**。要清零只能上内核驱动或把明文彻底移出进程内存（当前 crypto 已到 Java 侧地板 ≈74 类）。
8. `--verify` 只链接明文 loader/helpers（既有契约）；加密 payload 的运行期正确性由 loader 自检。

## 5. 结论

- **闸门**：26/26 runner + 双 seed 端到端全绿；3.69 MB / 1143 类 vs 改造前 3.26 MB / 1506 类（**类数 −24%，体积 +13%**，体积涨在 VM holder 上）。
- **真正被堵住的**：
  - **W1（致命）**：明文 32B seed 消失，A2 全灭 13 秒脱壳变成「必须逆 native」；
  - **W11**：v5 + native digestKey + 覆盖解密后字节 → A6 连索引都封不出来；
  - **W3/W4**：可消去熵形态 grep=0，谓词折叠量 −53.9%；
  - **W8**：转发桩目标常量 100%→0%；**W9**：共享 256 表 1→0；**W7**：命名可预测性 + 伪库包；**P9**：CFR impossible-loop 0→60/527。
- **W12 已封住「内存换空方法体」这条路**：单门无效（766/768）→ 双门 12 → 判定权搬进 DLL 后，patch4/patch5 全部 exit 1、只有 11 个引导类。残留「启动后 attach」「自定义 JVMTI agent」两条待补测。
- **一句话**：从「读产物 13 秒脱壳」变成「必须运行 + 逆 native + 逐载荷付代价」；但「运行期 patch」这条门还开着，报告不掩饰它。