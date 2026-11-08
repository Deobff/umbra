# java2c（NativeCodePass）现状与优化计划

> 结论先说：**它不是要新增，是早就有但一直关着**。本轮第一次把它打开实测，
> 发现产物跑不起来——这正是它从没被验证过的证据。

## 0. 状态快照（2026-11-07，crypto 实测记录）

**已修复并验收（2026-11-07）：`native.enabled=true` 端到端跑通，5/5 干净运行。**
仍默认关闭（`native.enabled=false`）：它是成本型保护，不是默认档位的一部分。

```
Lead 验收（build-v60）：
  protect: native-loader-digest pinned ... (digest=72bb02fe...)  artifact=True
  run    : NATIVE-OK 1e3b56e6
  clean  : 5/5
```

**最后一环的根因（两处，缺一不通）**：
1. `_m.name = cName`，空则 `return -7`（fail-closed）——原先保留 `? _name` 兜底，
   而 `_name` 的初始化已删 → 空名时传**野指针** → JNI 硬崩（`mid` 都打不出来）；
2. `bindOwnNames` 按描述符找名时**必须过滤 `ACC_NATIVE`**——`(I)J` 在 loader 类上有两个方法
   （native `verifyChallenge(int)` 与 Java 包装 `mixChallenge(int)`），取先命中的会拿到没有 native body 的那个。

已打通（同一产物、可复现）：

| 环节 | 证据 |
|---|---|
| 码库密封（jar 内无明文 PE） | `.dat` 走密封资源；`jar xf` 后无 `4d 5a 90 00` |
| V27 loader 自校验 | 四个值全等：`entry sha256 = verify sha = 29834b7c…`、`key = 373f4c5f…`、`pin digest = verify digest = 474ffea4…`；bridge 自报 `umbra-state-pinned=1 diff=0 ready=1` |
| 索引解开（V15） | `openIndex ok`；`[diag] rootSha8=330885ef… commentB64=saao6xEc…(16B) label=class.master.v1` |
| 主路径（不含码库） | `--preset maximum` → Verification OK + `-Xverify:all` 运行 **OK** |

## 0.1 默认档 vs 实验档的 loader 保护深度（强度事实，必读）

默认档（`--preset maximum`，`native.enabled=false`）现在**不再因 native 自检失配而自杀**：
`loader 失配`永远致命；`bridge 失配`在默认档只打 ERROR 并继续（V28 已知限制：bridge 锚尚未以字符串
形式发布），在 `native.enabled=true` 档才致命。

**这带来一个必须写明的强度变化**：

> 默认档里改 loader 仍会在构造函数后段被 `Loader integrity check failed` 拦下，
> 只是拦截点从 native 退回了 Java 侧。

也就是说默认档的 loader 保护**没有消失**，但深度从「native 二进制锚」降到「Java 校验 + 索引里的
`d:loader` 摘要（keyed，缺 digestKey 无法重算）」。可以绕过它的唯一方式是**同一份 patch 同时改掉
`verifySelfBytes` 与其调用点** —— 那正是 V27 要 native 锚来接住的场景，因此默认档在这一层是
「有保护但可被同源 patch 绕过」，报告里不能把它写成「等价于 native 锚」。

数据（同一构建实测）：
```
--preset maximum                : loader-diff=0 bridge-diff=1 → ERROR 后继续 → RUN=0（输出 OK）
--set native.enabled=true       : loader-diff=0 bridge-diff=1 → self-verification failed (1) → exit 1
```
判定语义（位掩码优先，旧桥回退）：
```
mask 语义（新桥，探测以 "" ,"" 返回 3 判定）：1=loader 失配、2=bridge 失配、3=两者
  (rc & 1) != 0                → 永远 exit 1（有人改了校验逻辑）
  (rc & 2) != 0 && 锚健康       → exit 1（默认档与实验档一致）
  (rc & 2) != 0 && 锚不健康     → ERROR + 继续 + `umbra-anchor-unhealthy=1`
legacy 语义（旧桥，返回 1 表示「有失配」）→ 按 bridge 处理
```

## 0.2 V27 / V28：已修复（默认档与实验档都验证）

**V27（loader 条目被改）与 V28（bridge 条目无锚）均已闭合**，两个槽都参与判定：

| 项 | 状态 | 证据（默认档 `--preset maximum`） |
|---|---|---|
| legal | ✅ | `anchor-health loader=true bridge=true` → `diff=0/0` → `OK` → exit 0 |
| patch loader | ✅ | ASM 重建（合法类，`37729→37772` 字节）→ `loader-diff=1` → `self-verification failed (1)` → exit 1 |
| patch bridge | ✅ | ASM 重建（合法类，`15404→15447` 字节）→ `bridge-diff=1` → `self-verification failed (1)` → exit 1 |

判据是日志里的 `umbra-hex-loader-diff` / `umbra-hex-bridge-diff`，**不是退出码**——
因为翻转字节常让 JVM 先报 `VerifyError`/`NoClassDefFoundError`，那不能证明自校验生效。
复跑方式见 `qa/verify/PATCH-ACCEPTANCE.md` + `qa/verify/RewriteClass.java`。

**锚健康门（I13）**：启动时用两次「故意错值」探测判断锚是否真的在拒；
两槽都拒 → 本次启动 strict；任一槽不拒 → 报告 + `umbra-anchor-unhealthy=1` + 继续。
这样「锚坏」不会误杀合法产物，「锚好」时任何失配都致命。

**代码库绑定：已修复并验收（2026-11-07，Lead 实测）。**

```
--preset maximum --set native.enabled=true --seed 23303
  native-loader-digest: pinned ... (digest=ebf44366...)
  -Xverify:all -jar  x3  ->  J2C clean=3/3    first=NATIVE-OK 1e3b56e6
```

最后一环由两处修复共同闭合（缺一不通）：
1. `_m.name = cName`，空则 `return -7`（去掉未初始化 `_name` 的野指针兜底）；
2. `bindOwnNames` 按描述符找名时**必须过滤 `ACC_NATIVE`** ——
   `(I)J` 在 loader 上有两个方法（native `verifyChallenge(int)` 与 Java 包装 `mixChallenge(int)`），
   取先命中的会拿到没有 native body 的那个。

历史症状（已不再出现）：`umbra-bind-skip register` + `NoSuchMethodError: register`。

（`umbra-bind-sig=(ILjava/lang/Class;)I]` 里的 `]` 是**打印分隔符**，不在缓冲区里。）
需要的三个数：`umbra-bind-mid=0|1`、`umbra-bind-rn=<码>`、失败时 `ExceptionDescribe` 原文。

定位说明（写进报告）：java2c 是**成本型保护**——反汇编仍能看到符号与常量（红队在 V15 轮已证明），
它的价值是抬高静态分析成本，不是「不可读」。

## 1. 现有实现

| 组件 | 作用 |
|---|---|
| `NativeCodePass`（order 105） | 选择方法、生成 C、调 gcc、把方法改成 `native`、回填注册 |
| `NativeMethodTranslator` | 逐指令把字节码翻译成 C（模拟操作数栈） |
| `CGenerator` | 输出 C 源、运行时 helper、`JNI_OnLoad` 注册表、antiDump/antiBackfill |

开关：`native.enabled`，**默认 false**，`Presets` 里**没有任何预设打开它**。
也就是说 `--preset maximum` 的产物里从来没有 Java→C 翻译的方法。

## 2. 本轮改动：monitor 支持

改造前 `NativeMethodTranslator` 两处直接拒绝：
```java
throw new UnsupportedException("monitor instructions are not supported");
```
→ 任何含 `synchronized` 块的方法整类进不了 native。

现在翻译成 JNI：
```c
if (obj == NULL) { ThrowNew(env, NPE, "null monitor"); }
else { (*env)->MonitorEnter(env, obj); }   // / MonitorExit
if ((*env)->ExceptionCheck(env)) goto handler;
```
字节码本身已带 finally 形状的 MONITOREXIT，不需要额外合成 unwinding。

### 验证
造 `synctest.Shared`（`synchronized (LOCK)` 块 + `synchronized` 方法 + 1000 次自增）：
```
[INFO] native-code: translated 5 methods in 1 classes into a 278453-byte native library
       (134 translated JVM instructions, 0 skipped, 1 constructor bodies)
```
翻译链路跑通了；但**产物运行仍失败**，见下。

## 3. 阻塞：`maximum + native.enabled=true` 的产物静默 exit=1

- 同一 jar、同一 seed，只差 `native.enabled=true`：
  - 不开：`exit=0`，输出 `SYNC-OK`；
  - 打开：`exit=1`，**无任何输出**（`-Dumbra.debug=true` 也静默）。
- 已排除：翻译本身失败（日志明确 translated 5 methods / 0 skipped）。
- 待查：与门控/guard 的交互（正在用 `antiDebug.nativeGate=false` 对照）、
  以及 native 库加载失败是否被 guard 静默 fail-closed。

## 4. 优化顺序

| # | 项 | 价值 |
|---|---|---|
| 1 | 修「打开就静默退出」，并补一个 native-code 冒烟测试 | 让它从「死代码」变成「可交付」 |
| 2 | 在 maximum 里启用 + 覆盖率报告（哪些方法因何跳过） | 先量化再优化 |
| 3 | C 侧 try/catch 全链（区间跟踪 + 多 catch + 未捕获保留 pending exception） | 解锁带异常处理的方法 |
| 4 | JDK 调用内联（`System.arraycopy`/`Base64`/字符串） | 减少 JNI 往返 + 去 API 名指纹 |
| 5 | **把 loader/cipher/bridge 搬进 bridge DLL** | 直接解掉 V3 的核心类泄漏（见 SCOREBOARD） |

## 5. 与攻防赛的关系

R5 守方卡在「loader / cipher / bridge 被切成完整可读类」。这三件是**引导期必须存在的 Java 类**，
只要它们是 Java 类，就一定有可被雕刻的 CAFEBABE。第 5 项（native bootstrap）是这条泄漏的**结构性解**，
不是补丁。
## 6. 静默 exit=1 的定位结果

`-verbose:class` 显示最后加载的是 `java.lang.UnsatisfiedLinkError`：
**翻译出来的 native 方法没有对应实现**——要么 `JNI_OnLoad` 注册表没被调用，要么导出的符号名与注册项不匹配。
（同一产物在 `antiDebug.nativeGate=false` 下依然 exit=1，排除 guard 误杀。）

下一步修这个：
1. 检查生成的 C 里 `JNI_OnLoad` 是否被正确导出且被 `System.load` 触发；
2. 检查 `RegisterNatives` 的签名数组是否与 `MethodC` 的 desc 一致；
3. 加一条冒烟测试（1 个类、1 个 synchronized 方法）进 `qa/`，防止再次退化。
## 7. demo 全量实测（本轮新增）

`--preset maximum --seed 23303 --set native.enabled=true`，25 个业务类：
```
[INFO] native-code: translated 1028 methods in 25 classes into a 13880803-byte native library
       (502398 translated JVM instructions, 0 skipped, 17 constructor bodies,
        796 indy bridges, antiDump=sha256, antiBackfill=table+challenge/1028 entries)
[INFO] Pass native-code finished in 399554 ms
protect seconds = 410.1
```

### 结论（比预期好、也比预期差）

- **好**：覆盖率 **1028/1028、0 skipped**。monitor、异常、indy、构造器都吃下了；
  也就是说这套翻译器的能力其实够用，只是从没被打开过；
- **差 1**：**构建时间 410 秒**（约 7 分钟），瓶颈在 gcc 编译 13.8 MB 的 C；`, `--preset maximum` 的交付节奏无法接受；
- **差 2**：**产物没有生成**（`native-code` 打印完成后没有 jar），说明后续打包/校验环节有异常；
- **差 3**：小样本产物能生成但运行 `exit=1`（`UnsatisfiedLinkError`，见 §6）。

### 三个可执行的修法
1. **注册**：业务类从自身 `<clinit>` 调 `loader.register(classId, Owner.class)`；在自定义 ClassLoader 下 `FindClass` 解析不到这些类，改用 `env->GetObjectClass`/传入的 `jclass` 而不是按名查找；
2. **耗时**：C 里 50 万条指令 → 分段编译（每个类一个编译单元、`-O0` 或 `-Os`）+ 并行；或按 `native.maxInstructions` 大规模降采样；
3. **打包**：`native-code` 之后到 class-encryption 之间补一条「产物必须存在」的断言，失败要报错而不是静默。

## Known limitation: `native.enabled` is experimental (default off)

The java-to-C code library (`NativeCodePass`) still fails to bind its dispatcher on the
runtime loader: after `installCodeLibrary` loads the library and the bridge passes the real
method names, the library's `GetMethodID` on the loader class crashes the VM before it can
report a result (observed: logs stop right after `umbra-bind-sig=`, `run exit=-1`).

What is proven working around it:
- the bridge binds `keyRoot2`/`gate*`/`installCodeLibrary` with runtime names (v2 protocol);
- loader self-verification (`verifyLoader`) pins and matches the final loader bytes
  (`pinned=1 diff=0 ready=1`), and `openIndex` succeeds once the zip comment survives the
  late archive post-processor;
- `native.enabled=false` (the default) keeps the whole maximum preset green.

Therefore `native.enabled` stays **off by default** and is marked experimental until the
code-library binding is fixed.

## Known limitation (V28): the bridge class entry is not anchored yet

The bridge loader class (`<bridgeClass>.class`, the manifest entry point) still has no
integrity anchor: the build pins its sha into the .bin, but the runtime loader passes a
different byte image (observed `bridge-diff=1` while `loader-diff=0`), so the pin cannot
be satisfied yet. The loader-class anchor (V27) works and is verified.

Status:
- `verifyLoader` (loader slot): **working** — `pinned=1 diff=0`, `openIndex ok`, `RUN=0`
  for the maximum preset;
- bridge slot: pinned at build, mismatched at runtime; a rewritten bridge class is therefore
  **not** detected by this layer (its own fingerprint check still covers the .bin);
- `native.enabled` stays **off by default** and experimental.

Both sides must agree on one published entry name (`classEncryption.native.bridgeEntry`):
the pin pass already prefers that stat, and the loader must read the same entry.

## V28 update: bridge class entry anchor now works

Both slots (loader / bridge) are pinned with read-back proof and now compare correctly:

```
umbra-hex-loader-sha=be61fcb754bc5b8f   loader-diff=0
umbra-hex-bridge-sha=1e10735bcd5d4bff   bridge-diff=0
openIndex ok
NATIVE-OK 1e3b56e6
run exit=0            (maximum preset, seed 23303)
```

Root cause of the earlier `bridge-diff=1` (documented so it is not repeated): an extra pair of
magic byte arrays added for runtime slot lookup produced a **second copy** of the magic in the
image, so the build-time patch wrote the digest into the wrong copy while the real block kept
its 0xA5 sentinel. The fix removes the duplicate copies, reads the slots directly, and touches
each block's first byte so `-O2` cannot drop the initialiser.

Status: pinning and verification are wired end-to-end. The patch-attack cases
(loader byte / bridge byte) must be re-run by the crypto harness for the final sign-off;
`native.enabled` stays experimental until that run is recorded.
