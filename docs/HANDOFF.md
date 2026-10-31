# 交接文档 — Umbra 混淆器当前状态

最后更新：3.2.2 会话结束时。新会话请先读本文件，再读 `docs/ROADMAP-PORTS.md`。

---

## 0. 项目坐标

| 项 | 值 |
|---|---|
| 版本 | **3.2.2**（`Main.VERSION` / `GuiConfig.VERSION` / `build.ps1` / `README.md` 四处一致） |
| 工程根 | `C:\Users\Administrator\Desktop\MC\Umbra`（也可从 `E:\MC\Umbra` 访问，同一目录） |
| 只读参考快照 | `E:\MC\Umbra-repo`（10/23 原始仓库，**不要修改**，用于恢复被改坏的测试文件） |
| 参考实现库 | `C:\Users\Administrator\Desktop\MC\混淆器\`（7 个：ZKM、kbox、BytecodeVM、native-obfuscator、JNIC-Virtualization、PhantomShield、OpenYCP） |
| JDK（构建） | Zulu 8 `1.8.0_502`（默认 `java`/`javac`） |
| JDK（JavaFX GUI） | `C:\Users\Administrator\.jdks\corretto-1.8.0_462`（自带 `jfxrt.jar`） |
| C 工具链 | `E:\1111\bin\gcc.exe`（TDM-GCC 10.3） |
| 构建命令 | `.\build.ps1 -Task compile\|dist\|package\|test [-BuildDir <dir>]`；`build.cmd` |

---

## 1. 可交付成品（已构建并验证）

```
dist\umbra.jar          SHA256 99a3c571c480d68096fa64977c71b728d5895002b796dc0f8c885f09883838eb（1.22 MB，**不含旧 Swing 控制台**）
dist\umbra-gui-fx.jar   JavaFX 控制台（47 KB；由 gui-fx\build-fx.cmd 构建，`-Task dist`/`package` 自动刷新）
dist\umbra-3.2.2.zip    SHA256 8a00e0dfaa488b28ff7dd46eccc0be479a16772f91c06414d3b647cab82d84cf（zip 内的 docs\HANDOFF.md 是打包瞬间版本，比仓库少最后这次哈希回填）
dist\SHA256SUMS         覆盖 umbra.jar 与 zip
dist\Umbra.cmd          桌面启动器：**优先**起 JavaFX 前端，没有 JavaFX JDK 时回落到 jar 内旧控制台
dist\umbra-fx.cmd       只起 JavaFX 前端（jar 从 dist\ 或 gui-fx\ 自动定位）
dist\umbra-cli.cmd / umbra.example.yml
gui-fx\umbra-gui-fx.jar 工作树里的同一份 JavaFX 前端（源码 `gui-fx/src/io/umbra/guifx/`）
qa\redblue\run-redblue.ps1 红蓝对决评测器（8 行检查，见 §5）
qa\p01\cfr-quality.ps1     CFR 结构化率探针（P0-1 验收口径）
qa\gui-redesign\           GUI 截图、像素统计、选项审计、几何导出
docs\ROADMAP-PORTS.md      移植规格书（P0-1/P0-2/P0-3/P0-4/P1-5/P1-6 均已标记状态）
qa\otp-3.2.2\  qa\p01\     本会话的证据（压力/审计/CFR 数据、探针源码、套件日志）
docs\ARCHIVE.md            3.0/3.1 历史证据树已在 3.2.2 清理中删除，说明见该文件
```

**打包注意（踩过一次）**：`dist\` 以前只放 `umbra.jar`，而 `Umbra.cmd` 是 10/23 的旧启动器 → 双击 `dist\Umbra.cmd` 打开的是 jar 内的旧控制台，不是新 GUI。现在 `build.ps1` 的 `Build-Dist` 和 `Build-Package` 都调用 `Copy-GuiArtifacts`：把 `gui-fx\umbra-gui-fx.jar` 复制成 `dist\umbra-gui-fx.jar`，并同步 `Umbra.cmd` / `umbra-fx.cmd` / `umbra-cli.cmd` / `umbra.example.yml`；GUI jar 缺失时自动尝试 `gui-fx\build-fx.cmd`。验证：`UMBRA_LAUNCH_DRYRUN=1 Umbra.cmd` 在仓库根与 `dist\` 两个布局下都解析到
`javaw -cp "dist\umbra-gui-fx.jar;dist\umbra.jar" io.umbra.guifx.FxGui --jar dist\umbra.jar`。

验证结论（最后一次跑）：

```
25 个套件全绿（删掉旧 Swing GUI 后，`GuiLayoutTest` 随 `GuiSelfTest` 一起删除；日志 qa\final-test-nojgui.log + 单套件补跑）：
  AntiLlmTest 120 ✓      AuditTest 118 ✓        CantripTest 14 ✓
  CompatTest 215 ✓       CoreTest 149 ✓         CryptoTest 150 ✓
  DecompilerNoiseTest 114 ✓  DynamicGuardTest 239 ✓  FlowTest 260401 ✓
  GuiConfigTest 306 ✓    MinecraftAdapterTest 170 ✓
  MixinAnalyzerTest 147 ✓    MultiReleaseTest 37 ✓   NativeDynamicTest 190 ✓
  NativeGuardTest 95 ✓   NativeTest 110 ✓       NocturneCompatibleTest 14 ✓
  NocturneTest 101 ✓     OtpTest 17 ✓           ProtectionV2Test 144 ✓
  SecurityHardeningTest 127 ✓  StringHardeningTest 80 ✓  TypedSetTest 38 ✓
  Vm3Test 131 ✓          VmTest 548 ✓

demo --preset light/balanced/maximum：保护 0 → 运行 OK（otp-slots 0 / 138 / 293）；maximum 再加 -Xverify:all 仍 OK
SnakeGame.jar：maximum 保护后开窗口存活；`--set antiDebug.level=3` 下存活 10s、stderr 0 字节
红蓝（dist\umbra.jar 产物，balanced + classEncryption 关）：6/8（CFR 行 42% 通过，OTP 行通过）
  CFR 完全结构化率：balanced 58% → 42%（块重排前 → 后），maximum 8%
AntiLlm 跨类访问审计：非法跨类 private 引用 11 → 0；maximum 产物压力 800 次 → 0 失败
GUI：截图均值 (19,24,35) → (28,33,37)，旧调色板占比 55.4% → 0%，新 canvas 84.5%
```

---

## 2. 本会话已落地的改动（按时间）

| # | 改动 | 文件 | 效果 |
|---|---|---|---|
| 1 | **修两个过期测试断言**：`execMemoryScan` 自 3.2.1 起是 opt-in（level 2 关、level 3 开），`NativeDynamicTest` 仍按旧行为断言 | `src/test/java/io/umbra/tests/NativeDynamicTest.java` | 修掉 3.2.1 遗留的红套件（level 2 断言 + 正例检测显式开 `execMemoryScan(true)`） |
| 2 | **K-OTP 一次性程序状态（P0-2-a）** | 新 `core/runtime/UmbraOtp.java`；`RuntimeSupport.ensureOtp`（default）；`DefaultRuntimeSupport.ensureOtp`；`FlowObfuscationPass`（入口载体 + OTP 分支）；`Presets`（`otp.enabled`） | 每个被保护方法入口推进状态，`carrier & 1` 严格交替选 junk 分支；`light` 关闭，`balanced/maximum/aggressive` 开启 |
| 3 | **`--set <typed段>.*` 生效**（HANDOFF 旧 §3-3） | `cli/Main.java`（`--set` 循环后调 `UmbraConfig.applyTypedOverrides` + `base = b.build(false)` 刷新快照）；`core/config/UmbraConfig.java`（22 段 typed 解析工具，**不**在构造器里覆盖）；`docs/OPTIONS.md` | `--set renamer.enabled=false` / `flowObfuscation.level=aggressive` 等真的进 typed 段；优先级 预设 < `--set` < `--no-*` 等显式开关；YAML `options:` 里的 typed 键无效（YAML 段照旧） |
| 4 | **红蓝评测器加第 8 行**「一次性状态可复用」 | `qa/redblue/run-redblue.ps1`；`docs/ROADMAP-PORTS.md` | 判据：产物里有同时声明 `next()J`/`carrier()I` 的状态类，且入口 40 条指令内 `invokestatic carrier:()I` ≥ 5 点、覆盖 ≥ 2 类 |
| 5 | **新增套件** | `src/test/java/io/umbra/tests/OtpTest.java`（17）、`TypedSetTest.java`（38） | 状态机/并发/产物注入/入口调用点/入口分支位；typed 覆盖 + 派生配置回归守卫 + CLI 优先级 + 端到端 |
| 6 | **版本 3.2.1 → 3.2.2** + release notes + README | `Main.java`、`GuiConfig.java`、`GuiConfigTest.java`、`build.ps1`、`README.md`、`docs/RELEASE_NOTES.md`、`umbra.example.yml` | 产物可辨识；`umbra-3.2.2.zip` |
| 7 | **`DynamicGuardTest` 的 late-load 场景加一次重试** | `src/test/java/io/umbra/tests/DynamicGuardTest.java` | 子进程 24 次加载只要几毫秒，attach 与最后一次加载的窗口是调度竞态；一次 miss 属于测试假阴性，真回归会两次都失败。计数器在重试前回滚，最终计数稳定 239 |
| 8 | **修掉 maximum 产物的间歇性 `IllegalAccessError`（真根因）** | `pass/impl/AntiLlmPass.java`（跨类 decoy 块 + `promoteDecoy`/`samePackage`）、`tests/AntiLlmTest.java`（`decoysOf` 接受包私有） | `AntiLlmPass` 往别的类插 `invokestatic` 指向 `private static` decoy → 该指令第一次执行时抛 `IllegalAccessError`，守卫用 `nanoTime` 播种所以只在约 0.3% 的运行里命中。修法：跨类 decoy 提升为包私有 + 只挑同包目标。静态审计：非法跨类引用 11 → **0**；压力 800 次 → **0 失败** |
| 9 | **红蓝「OTP 不可观测」改为 N/A** | `qa/redblue/run-redblue.ps1` | 整包加密的产物测不了这一行时记 `[N/A ]` 并从分母剔除（默认 balanced 从 3/8 变 3/7），既不给白送分也不冤枉最强布局 |
| 10 | **P0-1 尾部：方法级块重排** | `FlowObfuscationPass.reorderBlocks`/`labelFor`；`Presets`（`flow.reorder`）；`tests/FlowTest.testFlowReordering`；`qa/p01/cfr-quality.ps1` | 把独立块抬出方法体、乱序追加、每条 fall-through 补 `GOTO`、原位置留跳转；balanced 206 方法搬 886 块、maximum 848 方法搬 6784 块，0 校验跳过。CFR 完全结构化率 balanced **58% → 42%**、maximum **8%**；红蓝 balanced 5/8 → **6/8** |
| 11 | **P0-2-c 字符串槽位按调用重加密** | `StringEncryptionPass`（双密文站点、`string.otpEngines`/`string.otpMaxSites`、`string.otp.sites`/`string.otp.engines` 统计）、`crypto/UmbraStringCipher`（4 个带 selector 的重载、`dualSiteId`、`decryptDual`/`dualHalf`、自检 `lastEngine()`）、`Presets`（两个新键）、`tests/StringHardeningTest`（+18 checks） | 站点存两份不同引擎的密文（`parts` 前半/后半，显式校验偶数与 half>0），调用点压 `invokestatic <otp>.carrier()I` 当 selector，低 bit 严格交替 ⇒ **同一站点连续两次调用必换引擎**；OTP 关/indy/超 cap 回退单引擎老路径。demo balanced：`otp-slots=138/16`，体积 +0.85%；maximum `293/32`。`FieldInitializationPass` 修完后「产物站点数 == stat」成立（178==178） |
| 12 | **P0-3 二层方言封签** | `UmbraCantrip`（`seal`/`decode`/`runSealed` + ChaCha20 + 每构建 opcode 置换表）、`VirtualizationPass.createCantripChunk`（`cantrip.seal`，默认开）、`tests/CantripTest`（+5 checks） | 方言文本先按 seed 派生的 128 项置换表替换、再 ChaCha20 加密、Base64 存储；产物里不再有可读的 `~value;.` 程序，解释器只暴露「解码+执行」。light+cantrip 产物 102 个 holder **全部**调 `runSealed`；balanced 产物 `OK` 且过 `-Xverify:all` |
| 13 | **`FieldInitializationPass` 死代码 bug** | `pass/impl/FieldInitializationPass.java`、`tests/CoreTest`（+3 checks） | 原来先放 `RETURN` 再 `add()` 追加常量赋值 → 所有被搬进 `<clinit>` 的静态常量都是死代码，字段保持默认值。改为插到 `RETURN` **之前**；测试断言 PUTSTATIC 在 RETURN 之前 |
| 14 | **JavaFX GUI 重写 + 贴 vfx 观感 + 修选项显示 bug** | 旧 `FxGui.java`（31KB 单体）+ `FxMotion.java` **删除**；新 `gui-fx/src/io/umbra/guifx/{FxGui,ConsoleModel,ConsoleShell,OptionsView,Motion,FusionButton,TitleBar,Tokens}.java`；重写 `umbra-fx.css`；`build-fx.cmd`（8 个源文件） | 布局：分段控件 + 卡片行 + targets 带；窗口改为 `UNDECORATED` + 自绘标题栏（拖拽/双击最大化/三键按 vfx 语义色 hover/右底角缩放）；按钮改 `FusionButton`（hover 时 accent 描边 150ms 淡入）；树改为两套控制模型的并集（修掉 19 个开关不可达）+ ui-only spec 不再渲染死开关 + 枚举越界值补进列表 + 整数截断记 note；新增 `selfcheck` / `audit-options` / `dump-command` 三个 QA 钩子。详见 §6 |
| 15 | **P1-5 原生壳（子集）** | 新 `jni/guard/GuardImports`（FNV 哈希名解析 8 个敏感 API）、新 `jni/guard/GuardLiterals`（33 条 sealed 字面量）、`GuardCodeGenerator`/`GuardDynamicCode`/`GuardFeatures`/`GuardOptions`/`NativeGuardPass`、`NativeGuardTest`/`NativeDynamicTest` | 导入表 **57 → 54**（导出表仍只有 `JNI_OnLoad` + `umbra_guard_tick`）；`strings` / `objdump -s -j .rdata` 里 `frida`/`gum-`/`jdwp`/`NtQuery*`/`CheckRemoteDebuggerPresent`/`CreateToolhelp32Snapshot`/`GetFileAttributesA`/`GetTickCount64` 等 21 条明文**全部消失**；函数级虚拟化明确不做 |
| 16 | **P1-6 原生内存保护 + 白名单** | `jni/guard/GuardDynamicCode`（代码段 CRC、页保护轮换、exec 扫描三层过滤）、`GuardFeatures`/`GuardOptions`（`DETECT_CODE_CRC`=1<<25、`DETECT_PAGE_GUARD`=1<<26、`antiDebug.execWhitelist`）、`NativeGuardPass` | 干净 JVM 误报 `0x4000000` 修好：根因是加载器把镜像数据页映射成 `PAGE_WRITECOPY(0x8)`，旧代码硬编码 `PAGE_READWRITE` 当稳态 → 首次轮换必误判。改为启动先写一次解决 COW + 实测稳态 + 命中自愈；`execMemoryScan` 加白名单后 SnakeGame 在 `level=3` 下 8s/40s 两轮均存活、stderr 空。`NativeDynamicTest` 118 → **190** checks |
| 17 | **删掉旧 Swing 控制台 + About + 标题栏收尾 + 打包** | 删除 `gui/{GuiMain,GuiRoot,GuiFrame,GuiDialogs,GuiPrefs,GuiModeOptionsDialog,GuiScreenshot,GuiSelfTest}.java`、`gui/ui/**`（18 个组件）、`gui/theme/**`、`tests/GuiLayoutTest`；`cli/Main.java`（无参 → 子进程拉起 JavaFX 控制台，找不到就打印 usage 并 exit 1）；`gui-fx/{TitleBar,ConsoleShell,FxGui,AboutDialog}.java`；`build.ps1`（`Copy-GuiArtifacts`、`gui` 任务改指 FxGui）；`AuditTest`/`GuiConfigTest` 去掉旧 GUI 断言 | 引擎 jar 从 1.51 MB / 481 类降到 **1.22 MB / 314 类**，`io/umbra/gui/` 只剩 4 个控制模型类（`GuiConfig`/`GuiModeOptions`/`GuiPresets`/`GuiSwitches`）。标题栏去掉 "protection console" 副标题、加 About 按钮（模态窗是**产品介绍**：一句话定位 + 7 层保护能力清单 + 底部一行版本/JVM，不再是路径和 JVM 参数表）；状态药丸 `minWidth=USE_PREF_SIZE` 修掉被挤成 "rd" 的截断；`-Dumbra.fx.about-shot` 可单独渲染 About。无参启动实测：有 GUI jar 时拉起控制台（新 javaw 出现、stdout 空、exit 0），没有时打印缺失项 + usage、exit 1 |
| 11 | **红蓝 CFR 行改口径** | `qa/redblue/run-redblue.ps1` | 旧口径数输出里的 `public class`（量到的是类修饰符），改成数「CFR 是否完全结构化」，判据用 ROADMAP 自己的 `<50%`；同时打印旧口径数字，两个数都在明细里 |

---

## 3. 已知缺陷 / 待修（按优先级）

1. ~~**maximum 产物的间歇性 `IllegalAccessError`**~~ **已修复（见 §2-8）**。根因不是 classEncryption loader：`AntiLlmPass` 的跨类 decoy 调用指向目标类的 `private static` 方法，`nanoTime` 播种的守卫让这条非法指令只在约 0.3% 的运行里第一次执行。证据链在 `qa\otp-3.2.2\stress\`（复现 880 次 / 3 次失败、解密探针、全量访问审计 11 条非法引用、修复后审计 0 条、压力 800 次 0 失败）。以后碰到"偶发 LinkageError"，先怀疑构建期插的跨类引用，而不是 loader。
2. ~~**P0-1 尾部**~~ **已完成（见 §2-10）**：`flow.reorder` 做方法级块重排，CFR 完全结构化率 balanced 58% → 42%、maximum 8%，红蓝该行 FAIL → PASS。注意它只改物理布局不改 CFG，所以压不到 0；下一档是**不可约控制流**（从循环外额外进入循环体的克隆块），属于新课题。
3. ~~**原生 guard 误报**~~ **已修复（见 §2-16）**：`0x4000000`（`DETECT_PAGE_GUARD`）在干净 JVM 上误报，根因是 `PAGE_WRITECOPY` 稳态假设；`0x40000`（`DETECT_EXEC_MEMORY`）的 AWT 误报由 `antiDebug.execWhitelist` + 三层过滤解决。现在 `level=3` 下 SnakeGame 存活、stderr 空。
4. **Minecraft/Forge 实机未验证**：Mixin 的 `package:` 依赖原包名，适配器会冻结这些类，但**必须进游戏实测**（原始 `台州商会B4.jar` 已不在工程内）。
5. **JavaFX 前端无自动化测试**：只有 `-Dumbra.fx.shot` 截图与 `-Dumbra.fx.autoprotect` 端到端两条自检。
6. **OTP 在 classEncryption 产物上不可观测**：红蓝脚本对整包加密的产物记 `[N/A ]` 并剔除分母（见 §2-9）；要看这一行的实际判据，用 `--set classEncryption.enabled=false` 的产物跑。想让红队脚本能解密后再扫，等于让它持有主密钥，不建议。
7. **`DynamicGuardTest` 的 late-load 场景在本机会稳定 miss 第一次**：attach 报 `AttachNotSupportedException` / marker 采样错过，重试一次即过（套件计数仍稳定 239）。已加“OS 拒绝 attach 就跳过 + 一次重试”的保护，但如果哪天两次都失败，说明 sticky 拒绝真坏了，不要再去加重试次数。跑全套时也不要同时跑别的 JVM 重活。
8. **`--rewrite-resources` 会整体覆盖 typed `resources`**：`Main` 里该开关用 `new ResourceOptions(true)`，会丢掉 `--set resources.obfuscatePaths`。属于该开关的既有语义，未改；要精确控制就别用这个开关，直接写 typed 段。

---

## 4. 剩余待做（`docs/ROADMAP-PORTS.md` 有详细规格）

| 项 | 内容 | 状态 |
|---|---|---|
| P0-1 尾部 | 方法级控制流重排（ZKM `MethodFlowAnalyzer`） | ✅ 已完成（3.2.2）：`flow.reorder` + `reorderBlocks`；CFR 结构化率 balanced 58%→42%、maximum 8%；`FlowTest.testFlowReordering` 覆盖语义 |
| **P0-2-a** | **K-OTP 运行时状态 + 方法入口推进** | ✅ 已完成（3.2.2） |
| P0-2-b | 原生种子（DLL 暴露 `otp_next()`） | ✅ 已完成（3.2.2）：`GuardCodeGenerator` 生成 `umbra_native_otp` + `JNI_OnLoad` 注册 `nativeNext(J)J`，`UmbraOtp` 绑定失败自动回退 Java；`NativeOtpProbe` 实测 `nativeBound()==1` |
| P0-2-c | 字符串/常量槽位按调用重加密 | ✅ 已完成（3.2.2）：双引擎密文 + `carrier()` 选择器；demo balanced `otp-slots=138/16`、体积 +0.85%；OTP 关/indy 回退单引擎 |
| P0-3 | 二层方言虚拟化（外层 ChaCha20 + 不同 opcode 表） | ✅ 已完成（3.2.2 子集）：`cantrip.seal` = 每构建 opcode 置换表 + ChaCha20 封签；**未做**「密钥来自外程序运行期状态」与「不同栈模型」（见 ROADMAP P0-3） |
| P0-4 | 调用图隐藏 | ✅ 已完成（跨类假边） |
| P1-5 | 原生壳（段加密/导入表合成/函数级虚拟化） | ✅ 子集完成（3.2.2）：导入表 57→54、明文标记清零；**函数级虚拟化不做**（周级，与验收无关） |
| P1-6 | 原生内存保护（先读 PhantomShield 的 33h/13cpp） | ✅ 完成（3.2.2）：代码段 CRC + 页保护轮换（实测稳态）+ `execWhitelist`；干净 JVM 零误报，SnakeGame level 3 存活 |
| 排除 | 云端授权/在线吊销/指纹绑定；BytecodeVM、native-obfuscator（比我们弱）；JNIC-Virtualization（是破解工具，只用于喂 anti-dump） | — |

---

## 5. 红蓝对决基线（`qa/redblue/run-redblue.ps1`）

口径：**8 行**检查（7 组攻击，其中「还原厂商包名」与「常量池算法名」同属明文符号组），得分 = 通过行数 / 实测行数。3.2.1 及以前是 7 行（4/7），行数变了，**不要把旧分母和新分母混着比**。整包被 `classEncryption` 加密时 OTP 行静态不可观测，脚本记 `[N/A ]` 并从分母剔除。

```
demo + balanced + classEncryption 关 + otp 开 + 块重排 : 6/8 (75%)   ← 3.2.2 基线（CFR 行 42% 通过）
demo + balanced + classEncryption 关 + otp 开（无重排）: 5/8 (62%)
demo + balanced + classEncryption 关 + otp 关（无重排）: 4/8 (50%)
demo + balanced（默认，classEncryption 开）           : 3/7 (43%)   ← OTP 行 N/A，剔除分母
ZKM 27                                                : 未按新口径重测（旧 7 行口径是 5/7）
```

CFR 行口径（3.2.2 起）：一个类只有被 CFR **完全结构化**（输出里没有 `Unable to fully structure code`）才算被反编译成功，判据 `<50%`。旧口径数的是输出里的 `public class` 字样，量到的是类修饰符（内部类/抽象类没有 `public`），会把「CFR 只能给 goto 兜底」的类误判成成功。明细里同时打印旧口径数字，便于和历史值对照。

CFR 结构化率（`qa/p01/cfr-quality.ps1`，24–25 个带守卫的类）：balanced 无重排 58% → 有重排 **42%**；maximum **8%**。

新增行明细（正例）：`37 entry carrier() call sites in 18 class(es), 344 carrier() sites in 25 class(es) total (need >=5 entry sites in >=2 classes)`（3.2.2 起双密文站点的 `carrier()` 也算调用点，所以从 36/17 涨到 37/18；总站点 206 → 344）。

用法：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\qa\redblue\run-redblue.ps1 -Jar <产物.jar> [-Dll <lib.dll>] [-Label name]
```

---

## 6. JavaFX GUI（`gui-fx/`，3.2.2 重写）

**3.2.2 的 GUI 是重写的，不是改样式**：旧的单文件 `FxGui.java`（31 KB 单体 + 一个 `FxMotion`）整个删掉，换成 6 个职责单一的源文件，布局也换了（自定义分段控件 + 卡片行 + targets 带，不再用 `TabPane`）：

| 文件 | 职责 |
|---|---|
| `FxGui.java` | Application：生命周期 + 无头自检钩子（shot / autoprotect / exitWhenDone / reduceMotion / selfcheck / `--jar`） |
| `ConsoleModel.java` | 控件状态、targets、`command()`（预览与真正执行的唯一来源）、`presetValues()`（读 `--dump-preset`）、`engineArguments()` |
| `ConsoleShell.java` | 窗口骨架：header（品牌 + 状态药丸）、rail（树 + 汇总）、workspace（分段 + 三个视图）、bottom（targets + 动作条）；拥有进程、日志、状态 |
| `OptionsView.java` | 一个配置组 = 一张卡；行 = 左标签/键提示 + 右控件；重建时 30ms 错峰入场 |
| `Motion.java` | 动效原语：按压 0.97、行入场、视图切换、窗口入场、状态脉冲；`reduceMotion` 全归零 |
| `FusionButton.java` | vfx fusion 按钮：静止是 raised + 1px 描边，hover 时**描边在 150ms 内淡入 accent**（不是整块变底色），按下用 vfx 的 down 色 |
| `TitleBar.java` | 自绘窗口标题栏：品牌 + 状态药丸 + 三个窗口按钮（关闭红 / 最大化绿 / 最小化琥珀 hover）、拖拽移动、双击最大化 |
| `Tokens.java` | 设计令牌（颜色/圆角/rail 宽度/状态色），与 CSS 字面量成对维护 |

```
构建：gui-fx\build-fx.cmd   （自动探测带 JavaFX 的 JDK 8，可用 JFX_JAVA_HOME 覆盖；编译上面 8 个源文件）
启动：umbra-fx.cmd
截图：java -Dumbra.fx.shot=<png> -cp "gui-fx\umbra-gui-fx.jar;dist\umbra.jar" io.umbra.guifx.FxGui
结构自检：java -Dumbra.fx.selfcheck=1 ...   → "selfcheck: PASS (0 failures)"
选项审计：java -Dumbra.fx.audit-options=<txt> ... → "audit: CLEAN, 30 note(s)"（见下）
几何导出：java -Dumbra.fx.dump-geometry=<txt> ... → 每行 slider/readout 的 scene 矩形
节点带导出：java -Dumbra.fx.dump-band=<txt> ... → 指定 y 区间内所有带背景/边框的节点及矩形
命令导出：java -Dumbra.fx.dump-command=<txt> ... → 把预览命令写到文件（QA 断言用）
端到端：java -Dumbra.fx.input=<jar> -Dumbra.fx.output=<out> -Dumbra.fx.preset=balanced -Dumbra.fx.autoprotect=1 -Dumbra.fx.exitWhenDone=true ...
静默：-Dumbra.fx.reduceMotion=true 或 -Dumbra.fx.animations=false（动效全归零，终态保留）
```

**窗口 chrome（贴 vfx）**：`StageStyle.UNDECORATED` + 自绘 `TitleBar`（46px，panel 底 + 1px 下边框）——拖拽移动、双击最大化（最大化后按钮变 ❐）、三个窗口按钮按 vfx 的语义色 hover（close→`#d1584f`、max→`#59b655`、min→`#d8a23a`）；右侧/底部/右下角 6~14px 拖拽条负责缩放（无边框窗口没有原生边框）。

**选项显示 bug（本轮修掉的真实问题）**：
1. **19 个开关在 UI 上根本看不见**：`GuiSwitches` 与 `GuiModeOptions` 是两套分类（各 12 组，只有 4 个组名重合），旧树只按 `GuiModeOptions` 建组 → `Data(4)`、`Control flow(4)`、`Archive(3)`、`Anti-analysis(5)`、`Verification(3)` 里的开关全部不可达。现在树是**两套组的并集**，且只收录「至少有一个可渲染开关」的开关组（全被 spec 覆盖的组不建条目，避免打开是空卡）。
2. **ui-only spec 变成死开关**：`Output` 组里的 `gui.verify` / `gui.seed` / `gui.mapping` 是 UI 自己的字段（无 engine key），渲染成控件也不会生效 → 现在跳过，真正的控制在 targets/动作条里。
3. **枚举值不在声明列表里 → 空白下拉**：预设可能给出控件模型没列出的值（如 `auto`），旧实现 `setValue` 后显示空白；现在把该值补进列表并记 note。
4. **整数越界被静默截断**：现在截断后写审计 note（`int value 'X' clamped to Y`），滑杆还按 `step` 吸附。
5. 布尔值兼容 `true/1/on/yes` 与 `false/0/off/no`（预设可能写 `1`/`on`）。

**选项审计**（`-Dumbra.fx.audit-options`）：逐组渲染一遍，检查「可渲染开关数 vs 实际行数」「spec 是否都有控件」「ui-only 是否带 key」「空标签」「重复 engine key」「枚举/整数/布尔值是否与控件表示一致」，并把「开关的 key 被 spec 接管」列为 note。最后一次结果：**CLEAN，30 note(s)**（30 条 note 全是「该 key 由 spec 控件负责」的说明，不是缺陷）。

**滑块轨道压字（截图上"字夹在滑块里"的根因与修复）**：JavaFX 8 的 `SliderSkin` 按**首次布局时控件宽度**给 track 定尺寸，卡片随后缩到视口宽度时 track 不跟着缩（实测 `StackPane track [-117,444 2185x5]`），`#2b3237` 的轨道就从行首铺到读数标签底下。三处一起修：
1. 控件从 `HBox(滑轨, 读数)` 改成 **`GridPane` 两列**（列约束 200 / 46，读数 `maxWidth=46`），两列不会互相压；
2. 滑轨 `setPrefWidth(200)` + `setMinWidth(140)` + **`setMaxWidth(200)`**（Region 的 maxWidth 默认是 `MAX_VALUE`，不钉住就会被 HBox 拉伸）；
3. 给 Slider 挂一个**跟随控件尺寸的矩形 clip**（`clip.widthProperty().bind(slider.widthProperty())`），skin 无论怎么算错都画不出控件范围。
4. 窗口 show 之后 `settleLayout()` 重建一次选项行，让控件从第一次布局就拿到最终宽度。
验证（像素扫描 + 几何导出）：track 带宽度 **2185 → 183~206**，带内读数色像素 **0**；`sliderScene=853,440,200,13` / `readoutScene=1063,439,46,14` 不相交。

**设计系统**：石墨 ramp，取自 `E:\teeess\vfx-master` 的 dark theme（`io.vproxy.vfx`：scene `#24292e` / subscene `#171b1e` / accent `#4d6ebe` / progress `#59b655`），token 表写在 `umbra-fx.css` 头部与 `Tokens.java`：`canvas #171b1e` · `panel #1b2024` · `raised #24292e` · `hover #2b3237` · `selected #404952` · `stroke #2e363b` · `stroke-2 #46505a` · `text #ececec` · `text-2 #a9b3ba` · `text-3 #7d878e` · `accent #4d6ebe`（hi `#5d81d4` / lo `#3d5998`）· `ok #59b655` · `warn #d8a23a` · `danger #d1584f`。

**动效（按 emil 规则）**：树/分段/按钮是每天几十次或键盘可达 → 不做入场，只有指针 0.97 按压（110/140ms）；视图切换 160ms 交叉淡入；选项行 180ms + 30ms 错峰；窗口入场 220ms（0.985→1，不从 0 开始）；状态点每次变化脉冲 180ms。只动 opacity/transform，曲线 `SPLINE(0.23,1,0.32,1)`，全部 <300ms。

**客观验证**（模型看不了图，用像素统计；脚本 `qa/gui-redesign/check_redesign.py`，图 `rewrite.png` / `rewrite-reduced.png`）：
```
metric            before(旧 GUI)    after(重写)
mean              (19.1,24.2,35.1)  (30.0,35.1,39.6)   ← 蓝黑 → 石墨
luminance         23.93             34.32
share canvas      0.01 %            84.75 %            ← 新 canvas 铺满
share raised      0.07 %            9.28 %             ← 卡片/输入框/分段
share accent      0.00 %            0.63 %
share old_bg      55.41 %           0.00 %             ← 旧 #0e1118 清零
share old_accent  0.53 %            0.00 %             ← 旧 #4f8cff 清零
结构自检           —                 PASS (0 failures)：24 组树、3 视图只显示 1 个、主按钮样式类、状态点样式
端到端             —                 GUI 保护的 demo.jar 运行打印 OK
命令导出           —                 含 --preset balanced / flowObfuscation.maxInstructions=4000 / --verify
```

## 7. 操作踩坑清单（省下重复踩雷的时间）

1. PowerShell 里 `Man`/`R`/`Kill` 是内置别名（`help`/`Invoke-History`/`Stop-Process`），**不要用它们命名函数**；用 `Show-Manifest`/`RunJar`/`Remove-Tree`。
2. 函数内部输出会被 `$x = Build ...` 捕获 → 进度用 `Write-Host`，返回值单独 `return`。
3. **改文件前先 `Copy-Item x x.orig`**，且`.bak` 必须在第一次改动之前创建。
4. 用脚本做批量替换时，**逐行处理并跳过 javadoc**；`.Replace(...,3)` 在 .NET 4 不存在（只有 2 参重载）。
5. `edits`/文件写入要经过 `read` 工具读过才能用 `edit`；PowerShell 改文件后 `edit` 会报 “file changed since read”。
6. **`--set` 现在真的能改 typed 段**（3.2.2 起）：`--set renamer.enabled=false`、`--set flowObfuscation.level=aggressive`、`--set stringEncryption.minLength=3` 都生效。优先级：预设 < `--set` < `--no-*` 等显式开关；映射只发生在 CLI 装配阶段（`Main` 调 `UmbraConfig.applyTypedOverrides`），所以 YAML `options:` 里写 typed 键仍然无效（YAML 的 typed 段照旧有效）。`--set mapping.file=x` 不会连带改 `renamer().mappingFile()`（`RenamePass` 用后者写映射），要改输出映射用 `--set renamer.mappingFile=x`。
7. `-Task package` 不会重建 jar；`-Task dist` 才重建。打包前先 `Remove-Item dist\umbra.jar` 保证不是旧文件。
8. `dist\umbra.jar` 可能被正在运行的 GUI 锁住（`javaw -jar dist\umbra.jar`）→ 先关 GUI 或构建到 `-BuildDir` 再复制。
9. 运行 GUI 应用做冒烟测试要用 `Start-Process`/`Start-Job` + 超时，别直接 `java -jar`（会阻塞）。
10. `qa\redblue` 里检测守卫字段是**按字节里出现 `z$f0`/`z$f1`** 判断（用 javap 正则会被 PowerShell 转义坑）。
11. **用 `Set-Content`/`Out-File -Encoding utf8` 改 Java 源码会给文件加 BOM**（PowerShell 5.1），javac 会报 illegal character。改完用 `[System.IO.File]::ReadAllBytes` 检查前 3 字节 `EF BB BF`，有就剥掉。
12. **不要在全套测试跑着的时候开别的 JVM 重活**（CFR 反编译、并行保护）：`DynamicGuardTest` 的 attach 采样会 flaky（见 §3-7）。
13. `-BuildDir <dir>` 会同时把 `dist` 指到 `<dir>\dist`，所以并行验证不会互相覆盖 `dist\umbra.jar`。
14. **偶发 `LinkageError`（`IllegalAccessError`/`NoSuchMethodError`）先用静态审计定位，别猜 loader**：`qa\otp-3.2.2\stress\` 里有现成的复现脚本（`stress-run.ps1 -Workers 16 -Rounds 50`）、解密探针（`probe\UmbraProbe`，`javap` 直接看加密产物会报"找不到类"）和全量访问审计（`probe\AccessAudit`）。这次的根因就是审计里那 11 条"跨类引用 private"。

---

## 8. 下一步（新会话从这里开始）

1. **P0-2-c 字符串槽位重加密**：`UmbraStringCipher` 的 `d(parts, siteSeed, siteId, engine)` 在构建期绑定 engine，需要每站点存双引擎密文 + 由 OTP bit 选，工作量在 `StringEncryptionPass`。
2. 然后 **P0-3 二层方言虚拟化** → **P0-1 尾部（方法级块重排，需先放宽 `FlowTest` 的派发器规格）** → **P1-5/P1-6**。
3. 每步完成定义：红蓝分数上升或该指标下降 + 目标 jar 能运行 + 全套测试绿 + `dist` 哈希更新 + 本文件更新。
