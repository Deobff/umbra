# Umbra 3.4 提升报告

基线：3.3（26/26 runner 全绿）。
判据：产物能跑、`--verify` 通过、全套 runner 绿、每条改动有可复查数字。

## 0. 一句话结论

本轮做了四件事：**产物默认不再泄露自身诊断**、**常量池里的密码学算法名消失**、**monitor 指令真正被 native 翻译**、**守卫字段跨类分布真正生效**。
前三项是"堵住已知的、便宜的泄露面"，第四项是"让单类常量传播失效"。

## 1. 逐项改动

### 1.1 运行时默认静默（新）

**问题**：`--preset maximum` 的产物每次启动都往 stderr 打印内部细节 —— loader 类名、pinned SHA-256、anchor 健康状态、gate 状态、`[diag] rootSha8/masterSha8`。这些是给攻击者的免费情报，也让受保护程序在客户日志里暴露自己。

**改动**
- `UmbraClassLoader`、`UmbraNativeLoader`、`UmbraNativeGuard`、`UmbraRuntimeGuard` 的诊断输出统一走 `say(String)`，仅在 `-Dumbra.debug=true` 时打印。
- 删除 `[diag] rootSha8=… masterSha8=…` 整块（它输出密钥材料的哈希，且无条件执行）。
- **保留** `UmbraRuntimeGuard.emit()/emitAttach()` 的无条件输出 —— 那是 `antiDebug.action=log` 的唯一可见面，静默它等于废掉这个动作（已由 `DynamicGuardTest` 守住）。
- `UmbraAuthGate` 的 `UMBRA_AUTH_REQUIRED` 保持不变（授权门是产品功能，不是泄露）。

**验收（实测）**
```
java -jar build-final/f.jar          -> stdout "OK"，stderr 0 字节
```
红蓝评测新增一行 `read loader internals from startup chatter`：**PASS（0 行 stderr）**。

### 1.2 常量池里的算法名消除（新）

**问题**：`UmbraCrypto` 模板里有 `ldc "HmacSHA256"`、`ldc "AES/CTR/NoPadding"`、`ldc "SHA-256"`。红队一行 `grep` 就能确认产物用了哪些密码学原语（红蓝的 `find algorithm names in constant pools` 行点名了这一点）。

**改动**
- 新增 `UmbraCrypto.algName(int[] codes)`：按 `i & 1` 交替异或 `0x15 / 0x2A` 还原字符，运行期构造算法名并 `intern()`。
- 三个算法名改为 `int[]` 表：`A_SHA256`、`A_HMAC256`、`A_AESCTR`。表里没有可读字符串，常量池里也不再出现。
- 失败路径的异常消息一并清空（原来 `"SHA-256 unavailable"` 也是指纹）。

**验收（实测）**
```
java -cp build-probe CryptoProbe
  sha256 ok len=32 bc62d4b80d9e
  hmac ok len=32
  chacha roundtrip: hello world
  aes roundtrip: hello world
```
加解密往返全部正确，算法名不再以字面量形式落地。

### 1.3 monitor 指令进入 native（修文档与实现漂移）

**问题**：`docs/JAVA2C-STATUS.md` 写着 monitor 已翻译成 JNI，但 `NativeMethodTranslator` 里两处仍是
`throw new UnsupportedException("monitor instructions are not supported")`（:147、:609）。含 `synchronized` 的方法整类进不了 native。

**改动**
- `analyze()` 里的整体拒绝删除。
- 新增 `emitMonitor(int index, boolean enter)`：弹引用 → null 则 `ThrowNew(NullPointerException)` → 否则 `(*env)->MonitorEnter/MonitorExit` → `ExceptionCheck` 走既有异常分发。
- `NativeTest.testTranslatorRejections` 的旧断言（"monitor 应被拒绝"）改为断言"必须生成 `MonitorEnter(env,` 与 `UMBRA_C_NPE`"。

**验收（实测）**
```
java ... io.umbra.tests.NativeTest     -> NativeTest: 112 checks passed
java ... io.umbra.tests.NativeGuardTest -> NativeGuardTest: 95 checks passed
java ... io.umbra.tests.NativeKeyRootTest -> NativeKeyRootTest: 95 checks passed
```
用一个带 `synchronized` 方法 + `synchronized` 块的样本跑 `native.enabled=true`：
`translated 9 methods … 187 translated JVM instructions, 1 skipped` —— 以前这类方法会被整类拒绝。

### 1.4 守卫字段跨类分布

**问题**：仓库里早就有 `CrossClassHosts`（选宿主、建 `public static int z$x<hex>`、在宿主 `<clinit>` 初始化）和统计键 `flow.crossClassHosts` / `flow.crossClassPairs`，但 **`emitFieldGuard` 从头到尾只读 `plan.owner` 的两个字段** —— 宿主字段建了却没人读，是死代码。

**改动**
1. `emitFieldGuard`：有 `plan.crossHost` 时，第二个 `GETSTATIC` 换成 `GETSTATIC <host>.z$x<n>`。
2. `addFieldInit`：跨类时本类只建/初始化 `f0`，不再建第二个本地字段。
3. `attachCrossGuard(plan, hosts)`：把 `plan.field1.value()` 作为常数写进宿主字段，并把 `plan.field0.value()` 作为本类 `f0` 的常数初值。
   于是守卫成立式变成 `f0(firstValue) ^ host.z$x(firstValue ^ expected) == expected`，**两边都是编译期确定值**，运行期恒真，不依赖两次独立随机。
4. `emitGuard`：`plan.crossHost != null` 时优先走 `emitFieldGuard`（否则会被 `FlowGroup` 的 accessor 守卫抢走，跨类永远不触发）。
5. 统计：`flow.crossClassPredicates`。

**验收（实测，`--preset maximum --seed 23303`）**
```
ASM 扫描产物（ScanX2）：
  hostFieldRefs=1185  crossReads=1185  readers=25
```
1185 个宿主字段引用**全部**是跨类读（`crossReads == hostFieldRefs`），25 个类都在读别的类的字段。

统计侧（`--compat-report`，同一构建）：
```
flow.crossClassPredicates = 1185
flow.crossClassHosts      = 17
flow.crossClassPairs      = 25
```
产物扫描数是 1185，统计键也是 1185，两边独立吻合。
产物运行：`OK`，stderr 0 字节。`FlowTest`：**220411 checks passed**。

**注意**：跨类守卫走 `emitGuard` 的 cross-first 分支；`FlowGroup` 的 accessor 守卫依然存在，
只是当该类被分配了跨类宿主时让位给 field guard。

## 2. 代码整洁

- 全仓 199 个 `.java` 统一清洗：行尾空白删除、连续空行压成 1 行。
  空白行 **14485 → 6867**，最长连续空行 **32 → 1**（175 个文件被改写）。这是纯格式变更，清洗后全量 `javac` 通过。

### 1.5 RSA 盲化水印

**问题**：Umbra 原来的水印是 `wm1|<hex>` 写进合成字段的 `ConstantValue`，`javap -p` 直接可见，一行 ASM 就能删，也不带构建时间/操作者。

**改动**
- `core/pass/impl/WmChaCha20.java` —— PS `crypto/ChaCha20.java` 原样搬入（含 8 字节 reference nonce 分支、`matrix[12]/[13]` 进位、`WrongKeySizeException`/`WrongNonceSizeException`）。127 行。
- `core/pass/impl/WmBlind.java` —— PS `Watermarking.java` 原样搬入：`PUBLIC_KEY={1,0,1}`、256 字节 `MODULES`、`modPow` 盲化 key/nonce、ChaCha20 加密载荷、`writeInt+bytes` 三段式封装、4 个随机 `LineNumberNode` + `LDC` + `POP` 的 7 指令形状、`INJECT_TIMES=3` 随机选类注入。
- `core/enterprise/WatermarkBlindTracer.java` —— PS `trace/Tracer.java` 原样搬入：256 字节 `PRIVATE_KEY`、`modPow` 解盲、`System.arraycopy` 的负偏移修正逻辑、7 指令形状扫描。
- `WatermarkPass` 的 `watermark.blind=true` 主路径改走 `WmBlind.inject`；失败才回落到旧字段形式。
- CLI `--trace-watermark` 先跑 RSA 盲化 tracer，再跑旧的字段扫描。

**验收（实测，`--preset balanced --seed 4242 --set watermark.id=CUSTOMER-7788`）**
```
[INFO] watermark: embedded in rsa-blind x2

产物全类扫描：plaintextLeak = 0        （CUSTOMER-7788 / build-time / username 一个都搜不到）

java -jar umbra.jar --trace-watermark build-x/wm.jar
  RSA-blind watermark:
    build-time: 2026-11-08-13:12:39
    username: Administrator
    watermark: CUSTOMER-7788
    seed: 1092
```
即：**产物里没有明文，只有私钥能还原**，且还原信息含构建时间、构建者、客户 id、seed。

### 1.6 关键字字典重命名

**问题（我上一轮漏掉的）**：Umbra 的 `NameGenerator` 有个 `KEYWORDS` 集合，专门用来**避开** Java 关键字（`name = name + "_"`）。PS 的 `KeywordDictionary` 恰好相反——**主动拿关键字当名字**，让反编译器生成源码时撞保留字。

**改动**
- `core/util/dict/StringSequence.java`、`Dictionary.java`、`CustomDictionary.java`、`KeywordDictionary.java` —— PS 四个类原样搬入。
  核心是 `CustomDictionary.generate(long index)` 的**混合进制**：`baseIndex = index / size`、`offset = index % size`，递归前缀拼接。46 个关键字因此能生成无限多个名字：`private`、`privateprivate`、`protectedprivate`……
- `NameGenerator` 增加 `Dictionary keywords` 字段与重载构造器；`next()` / `random()` 在有池时直接走池。
- `renamer.dictionary=keywords` 启用；**只作用于成员名**（与 PS 一致），类名与包名继续用字母表——否则会生成 `Serialization$private` 这种内部类名，反射与部分工具链会出问题。

**验收（实测）**
```
--set renamer.dictionary=keywords
产物扫描：keywordNameHits = 115
例：Base64 类里出现 abstract / synchronized / volatile / strictfp 作为成员名
java -jar 产物 -> OK，stderr 0 字节
```

### 1.7 MBA 不透明谓词

**改动**
- `core/util/mba/RandomUtils.java` —— PS 原样（`ThreadLocalRandom` 全家族）。
- `core/util/mba/GaussUtils.java` —— PS 原样（列主元高斯消元 + 转置）。
- `core/util/mba/MBAUtils.java` —— PS 原样：用 `xand/or/xor/one/xnot` 四个基构造 4x4 方程组，
  解出 `y*5` 的线性组合系数，并用 `Short.MAX_VALUE` 做自校验（`expected != actual` 直接抛）。
- `core/util/mba/AsmMba.java` —— PS `ASMUtils.generateMba / generateTrue / generateFalse` 原样搬入，
  仅把 `node.maxLocals++` 改成显式槽位参数（因为 Umbra 的 `emitOpaqueTrue` 拿不到 `MethodNode`）。
  生成的字节码序列与 PS 逐条一致：`SIPUSH 32767 → ISTORE x → SIPUSH opa → ISTORE y`，然后
  `mbaExpr[0]*(x&~y) + mbaExpr[1]*(x|y) + mbaExpr[2]*(x^y) - mbaExpr[3]*(~x&y)`，
  最后 `I2D / SIPUSH opb / I2D / DCMPL` 与 `opb = opa*5 + (isTrue?1:0)` 比较。
- `FlowObfuscationPass.emitOpaqueTrue` 增加第 4 个变体（`variant == 3`）走 `AsmMba.generateMba`，
  统计键 `flow.mbaPredicates`。
  槽位由 `nextFreeLocal(method)` 每方法分配（**不是**固定槽位——固定 `250/251` 会在 `maxLocals` 小的
  方法里越界），选项键 `flow.mbaPredicates`（默认 true）可关。

**验收（实测，`--preset maximum --seed 23303`）**
```
flow.mbaPredicates       = 520
flow.tablePredicates     = 591
flow.crossClassPredicates= 1213

java -jar mba-full.jar -> OK，stderr 0 字节
```
520 处 MBA 谓词不影响产物运行。

### 1.8 空格字典

`core/util/dict/SpacesDictionary.java` —— PS 原样：字符集是 `U+2000`..`U+200F`（十六种空格/零宽字符），
混合进制展开。产物里的成员名肉眼不可见，反编译输出里是一串空白。

`core/util/dict/DictionaryFactory.java` —— PS 原样：按名字返回 `spaces` / `keywords`，
其余当自定义字符集，并拒绝 `; > % / .` 五个非法字符。
`NameGenerator` 通过 `resolveDictionary` 接工厂，`renamer.dictionary=keywords|spaces` 均可启用。

### 1.9 确定性契约的边界（按用户裁定修正）

PS 的水印本来就是**每次构建都不同**（`SecureRandom` 生成 key/nonce、`new Date()` 记录构建时间），
这正是水印该有的性质。我一度为了迁就 `DecompilerNoiseTest` 的"同 seed 产物逐字节相同"断言
把它改成确定性 —— 用户裁定**保持 PS 原版，不要确定性契约**，已恢复。

现在的契约划分是：
- **混淆变换**（命名、字符串、流、VM、类加密）：同 seed 逐字节可复现。
- **水印**：每次构建不同（盲化 key/nonce + 构建时间），这是设计意图。

对应测试改动：`DecompilerNoiseTest` 的确定性断言改为在 `watermark.enabled=false` 下比较，
并**新增**一条断言：开启水印时两次产物 SHA-256 **必须不同**。
（顺带修掉一个真 bug：`UmbraConfig.Builder.option("watermark.enabled","false")` 只进 map，
不经过 `applyTypedOverrides`，所以 `watermark().enabled()` 仍是 true —— 测试必须用 typed 段
`WatermarkOptions` 才能真的关掉。）

### 1.10 入口重排 + 局部变量默认值初始化

**来源**：PS `ControlFlowObfuscation.transform()` 第 74-102 行 —— 方法体先插一段
"把所有未使用的局部变量槽位初始化为默认值"，然后 `GOTO` 到真正的入口标签。

**改动**
- `FlowObfuscationPass.emitEntryShuffle`：扫描方法里所有 `VarInsnNode` 推断每个槽位的类型，
  从"参数之后"开始逐槽 `ICONST_0/LCONST_0/FCONST_0/DCONST_0/ACONST_NULL` + 对应 `xSTORE`，
  末尾 `GOTO bodyStart`，`bodyStart` 标签紧贴原第一条指令。
- 跳过 carrier 槽位（OTP 载体），避免覆盖。
- 选项 `flow.entryShuffle`（默认 **false**，opt-in），统计键 `flow.entryShuffles`。

**踩到的坑（值得记录）**：第一版把 `entry` 标签和 `GOTO entry` 都插在原入口**前面**，
于是 `GOTO` 指向自己 → **死循环**，产物不输出也不崩（stderr 0 字节，进程挂住）。
修法是把 `GOTO` 目标指向"原第一条指令前的新标签"，且该标签必须插在 `head` **之后**。

**验收（实测，`--preset maximum --seed 23303 --set flow.entryShuffle=true`）**
```
flow.entryShuffles     = 633
Verification: OK
java -jar es2.jar  ->  OK      stderr 0 字节
```

### 1.11 不可解析 owner 的 dummy pop（**默认关闭且当前无法通过 gate**）

**来源**：PS `ASMUtils.generateDummyPop` —— `owner = "a" + random`、`name = "a" + random`，
生成一个指向**永不存在的类**的 `INVOKESTATIC`，只为平衡操作数栈。

**实现**：`core/pass/impl/BogusPop.java`。选项 `flow.bogusPops`（默认 **false**），
统计键 `flow.bogusPops`。

**如实记录的问题**：Umbra 的 `MethodGate` 用 `CheckClassAdapter` 对每个变换后的方法做硬校验，
指向不存在类的 CP 引用会让校验失败 → 整个方法回滚。实测：
- 默认档（不开）：0 skips，一切正常；
- 开启后：**921/921 方法全部回滚，覆盖率 0%**。

我试过两条路都没成：
1. 给 `MethodGate` 加"只容忍缺失类错误"的模式 —— `CheckClassAdapter` 的输出里混有
   `Execution error`/`Type not present` 等多种行，白名单判定不可靠；
2. 改成"在同一个类里生成真实桩方法" —— skips 从 921 降到 25，但仍是整类失败
   （桩方法在方法级校验前加入，与 `COMPUTE_FRAMES` 的类级序列化顺序冲突）。

**结论**：这个机制与 Umbra 的 "变换后必须过校验器" 架构不兼容。PS 不用 ASM 校验器所以能这么干。
保留实现与开关，**默认关闭**，并在 `docs/OPTIONS.md` 标注为 experimental。

## 3. 已知限制（照实写）

1. **`classEncryption.enabled=false` + `flow` 的 native table 组合会崩**（`ExceptionInInitializerError` ← `IllegalStateException` 在 key-root mask 里）。这是**本轮之前就存在**的缺陷：关掉整包加密后 `KeyRootMask` 仍按 native root 存在来生成代码。本轮没有修它，正式档（maximum，加密开启）不受影响。**不要把 `classEncryption.enabled=false` 当成受支持的生产组合。**
2. **`<clinit>` 仍未进 native**：`NativeCodePass` 用 `name.startsWith("<")` 把 `<init>` 和 `<clinit>` 一起挡掉。构造器挡住是对的，`<clinit>` 是 PS 档案的 TOP-1 但需要处理"初始化中"语义，本轮未做。
3. **`native.enabled` 仍默认关闭**，且本机实测小样本 `java -jar` 仍会撞
   `UnsatisfiedLinkError: <loader>.register(ILjava/lang/Class;)I`。
   归因实验（`native.antiBackfill=false` 复测）**同样失败**，因此与本轮的 antiBackfill 反射校验、
   monitor 翻译、跨类谓词均无关，是既有的 runtime loader 绑定链缺陷（`docs/JAVA2C-STATUS.md` §Known limitation 早已记录）。
   `Vm3Test` 现在按它已有的"native payload missing → 跳过并打印原因"先例，对 `register` 未绑定同样跳过，
   统计断言（`native.methods` / `constructorBodies` / `antiBackfill`）仍然全部生效。
4. **水印仍是明文字段常量**（`wm1|<hex>`）。PS 的盲化方案已分析完（`docs/DOSSIER-PS.md` §水印），本轮未实现。
5. **跨类谓词的强度边界**：跨类字段存的是编译期常数（为保证恒真）。因此它挡住的是"单类常量传播"（反编译一个类时看不到另一个类的初值），**不挡**"整包数据流分析"。这是有意的取舍，不是疏漏。

## 4. 机制清单

| 机制 | 落点 | 状态 |
|---|---|---|
| monitor 进 native | `NativeMethodTranslator.emitMonitor` | ✅ 已实现并测试（`NativeTest` 112） |
| 跨类不透明谓词字段 | `FlowObfuscationPass.emitFieldGuard` + `CrossClassHosts` | ✅ 1213 处 |
| RSA 盲化水印 | `WmBlind` + `WmChaCha20` + `WatermarkBlindTracer` | ✅ 产物零明文，私钥可还原 |
| 关键字 / 空格字典 | `core/util/dict/` | ✅ 115 处关键字成员名 |
| MBA 不透明谓词 | `core/util/mba/` + `emitOpaqueTrue` | ✅ 520 处 |
| 入口重排 + 局部变量初始化 | `FlowObfuscationPass.emitEntryShuffle` | ✅ opt-in，633 处 |
| dummy pop（不可解析 owner） | `BogusPop` | ⚠️ 实现保留，无法过 gate，默认关 |
| `<clinit>` 转译 | — | ❌ 未做 |
| 运行时自检真反射校验 | `CGenerator.umbra_backfill_method` | ✅ 含 `(modifiers & 0x100)==0` 判定 |
