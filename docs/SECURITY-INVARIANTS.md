# 安全不变量（每次交付前自查）

> 每条都对应一次被攻方打穿的记录：**来源**（哪一轮/哪个漏洞）、
> **违反检测点**（代码里在哪拦）、**反例**（本场真实发生的那次，带数字）。
> 只收被真实攻击或真实故障验证过的条目；「我们觉得应该有」的原则不在此列。

---

## I1 · 关键保护缺失时不得静默降级

- **来源**：V8（`rooted()` 在 `root == null` 时返回 `concat(tag,args...)`）、
  V5/V6（库 jar 未密封 / 库模式 seed 明文）、更早两次（bridge 编译失败、seed 回退）。
- **违反检测点**：`ClassEncryptionPass.skipOrFail`（无入口/Eclipse jar/loader 名冲突 → 失败，
  除非显式 `classEncryption.allowSkip=true`）；`StringEncryptionPass.resolveKeyRoot`（无 key 且无
  `string.allowKeylessFallback=true` → 失败）；`UmbraEngine.discardOutput`（任何 pass 抛错 → 删除产物）。
- **反例**：V8 的 `string.indy` 在无根时退化为可逆变换，**184/184 个站点**纯离线可还原。

## I2 · 失败必须显式可观测

- **来源**：V5（库 jar 未密封静默放过）、V6（库模式 seed 明文）、V14/V15（`installCodeLibrary` 静默死亡）。
- **违反检测点**：`UmbraClassLoader.installCodeLibrary`（无条件打印 entry / 异常 / 栈）；
  `openIndex` 的 `[diag]` 行；任何 skip 必须同时写 stats（不允许只写日志不写 stats）。
- **反例**：`installCodeLibrary` 在 native watchdog 杀掉 `%TEMP%\ums*.tmp` 时**进程直接消失**，
  无异常、无栈；加无条件诊断后才定位到 watchdog。

## I3 · 归档内不得出现密钥材料

- **来源**：V6（`SITE_SEED` 明文常量）、V25 前置（库模式「无 key 必败」的可验证前提）。
- **违反检测点**：`qa/verify/VerifyLibraryKey.scanForKeyMaterial`（遍历明文类，
  检查 `SITE_SEED`/`BINDING_SEED`/旧串 `embedded seed binding`）；构建期 `stripSeedFallback`。
- **反例**：V6 的库 jar 带 base64 seed → **1832/1832 类离线可解**；修复后同一扫描
  `hits=0`（`SELFTEST PASS` 输出）。

## I4 · 溯源标记必须带秘密

- **来源**：V7（`sha256(id|seed)[:8]` 无盐）、V26（红队想抹掉 `wm1|<token>` 必须先重算摘要）。
- **违反检测点**：`UmbraCrypto.keyedDigest(digestKey,"d:serial"/"d:c:"+name,…)`；
  `ClassEncryptionPass` 的 `d:serial` 与每类摘要；运行期 `verifyClassDigest`。
- **反例**：V7 用 **1181 词字典**反推出客户 id；V26 穷举 **48 组** label/root/data 组合
  （`d:c:`/`c:`/`d:`/空/`class:`…）**全未命中**，按 `KEYED-DIGEST.md` 才复算出 `bac53901…d37a`。

## I5 · 可执行层与库层强度要一致

- **来源**：V5/V6（可执行 jar 有 native root，库 jar 只能 seed）。
- **违反检测点**：`ClassEncryptionPass` 的 `BINDING_HOST=3` 分支；
  `UmbraLibraryBootstrap.open(File, byte[])`（32 字节宿主根）；无外部密钥的库模式**不许出产物**。
- **反例**：V6 前库产物靠 `@@SEED@@` 自解密，等价于把钥匙贴在锁上。

## I6 · 形态不构成安全

- **来源**：V4（把 `A^B` 换成打包串，脚本照样能解）。
- **违反检测点**：验收标准必须是「**静态不可解**」，不是「某个工具折不动」；
  任何「换编码/换引擎/换宽度」只能当过渡。
- **反例**：V4 的红队脚本对换编码后的产物仍可还原全部字符串。

## I7 · 交付前必须自攻一次

- **来源**：全场（V1–V27）；`native.enabled` **从未被打开过**。
- **违反检测点**：`native.enabled` 默认 false + `docs/JAVA2C-STATUS.md` 的 experimental 标注；
  CI 必须跑 `--preset maximum`（含 `-Xverify:all` 运行）。
- **反例**：`native.enabled` 第一次打开就**跑不起来**（构建成功、启动即死）——
  「没自攻过」的直接证据。

## I8 · 指标必须报告在最弱单元

- **来源**：V20（`coverage 100%` 掩盖 `too_large` 跳过）。
- **违反检测点**：`FlowObfuscationPass` 的 `flow.coveragePercent` + `flow.skip.*` 单独计数
  （`skip.tooLarge` **不并入**覆盖率）；`flow.requireCoverage` 未达即失败；审计 JSON 同时带分子分母。
- **反例**：某轮报 `1832/1832` 与 `300/300 分支`「全处理」，实际只做了外形
  （`table=static`），`too_large` 类整类跳过。

## I9 · 「防住了」的结论必须可复算

- **来源**：V24（`keyedDigest` 文档缺口）、V25（库模式无 key）。
- **违反检测点**：`qa/verify/VerifyDigest.java` 与 `qa/verify/VerifyLibraryKey.java` 的
  `--selftest`（正例 0 / 反例 1 / 坏输入 2）；`qa/verify/KEYED-DIGEST.md` §7 的三态表。
- **反例**：`VerifyDigest` 曾把 `System.exit(1)` 写在 try 内 → 失败路径**隐式返回 0**（假绿）；
  改为单一出口后 `--selftest` 五例全过（含真篡改 → `MISMATCH=1`）。

## I10 · 密钥派生输入必须集中声明

- **来源**：V15（ZIP comment 被当成「元数据」，实际参与 master 派生）。
- **违反检测点**：`UmbraCrypto.masterFromRoot(root, commentBytes, entryCount)` 的唯一调用点
  （构建 `ClassEncryptionPass`、运行 `UmbraClassLoader.openIndex`）；
  `ClassEncryptionPass.assertZipComment`（写完读回校验）；`UmbraEngine` 的终局 comment 检查。
- **反例**：`build: commentB64=EbnlkrlI…` / `run: commentB64=<null>` →
  `masterSha8` 从 `a73a225b` 变成 `aafd3104` → `openIndex` 报 root/key mismatch。

## I11 · loader 锚定必须在最后一个改写它的 pass 之后

- **来源**：V27（pin 的是 bridge 类，patch 的是 loader 类）。
- **违反检测点**：`ClassEncryptionPass` 在 `d:loader` 写入处发布
  `classEncryption.loaderEntry` / `classEncryption.loaderSha256`（代码里带 INVARIANT 注释）；
  native 的 `native-loader-digest` 必须注册在 order 200 之后并读这两个键。
- **反例**：V27 三次失败（先验字节、再验错类、最后 pin 与 verify 指的不是同一个类：
  `verifyLoader entry=n0luNbJqVKxoRWT.class`（bridge）而红队 patch 的是 `n0luLZmll19Fxjf.class`（loader）
  → `umbra-state-diff=0` 却照样运行）；V28 再证 **bridge 的 `.class` 条目本身完全无锚**
  （改 magic → `ClassFormatError` 证明被解析；翻 offset 200 的 1 字节 → `exit=0` 输出 `OK`）。
- **现行检测点**：`verifyLoader(String loaderSha, String bridgeSha)` 首选，运行期三层回退
  `(String,String)` → `(byte[],byte[])` → `(byte[])`，**降到第三层时运行期打 ERROR**
  （此时 loader 完全没被 native 校验）；`native-loader-digest` 读构建期 stats
  `classEncryption.loaderEntry` / `classEncryption.loaderSha256`；`classEncryption.loaderVerify`
  记录桥支持哪一形态（`sha(loader+bridge)` / `legacy(loader unverified)`）。
- **强度（不美化）**：sha256 锚是**无密钥**完整性：攻击者能自己算 sha，但必须同时改 `.bin` 里的锚
  **且**重算 `.bin` fingerprint，且算法在 DLL 内 —— 比「完全无锚」强，但**不等于**密钥绑定
  （无 key 的攻击者仍可在拿到构建产物后伪造一份自洽锚）。

## I12 · 任何比对的两侧必须证明是同一个对象

- **来源**：本场出现 6 次：旧 jar vs 新代码、跨构建比 sha、`static const` 折叠、
  归档条目 vs 运行期副本、`_name` vs `_m.name`、bridge 类 vs loader 类。
- **违反检测点**：任何 `assert(sha_a == sha_b)` 之前先打印两侧**来源标识**
  （文件名/类名/长度）；`UmbraClassLoader.verifyOwnClassBytes` 打印
  `entry=<name> len=<n> sha=<hex>`；`ClassEncryptionPass` 打印 `entry sha256 / pin key / pin digest`；
  不一致直接 fail-closed。
- **两个子项**：
  - **I12a · 数据侧**：比对前打印两侧来源标识（文件名/类名/长度/sha），不一致直接 fail-closed；
  - **I12b · 能力侧**：方法/键/开关的**存在性不等于语义已实现**，必须**行为探测**；
    且**探测结果只能用于选择语义，不能参与放行决定**（否则探测本身变成漏洞）。
- **反例（按重要性排序）**：
  1. **能力侧**：`verifyLoader(String,String)` 存在 ≠ 掩码语义已实现。第一版据此把旧桥的 `rc=1`
     当成「loader 被改」→ **默认档 `--preset maximum` 被打回 `exit=1`**；加能力探测
     （`verifyLoader("","")`：mask 桥返回 `3`、旧桥返回 `1`）后才正确。
  2. **数据侧**：`verify sha=4a6200a1…` vs 红队给的 `原始 2d535e3c…` / `patched 61e8e304…`，
     三者互不相同 —— 比较的两侧根本不是同一个对象。
  3. **数据侧**：`umbra-state-diff=0` 却放行了被打补丁的 loader（验的是 bridge 类）。
- **共同错误形态**：拿一个**近似的信号**当等价物（存在性当语义、不同构建的字节当同一份）。

## I13 · 锚不可靠时可以降级，但必须能自动恢复严格

- **来源**：R67 的 P0 + V28。为保住默认档一度把 strict 关掉（当时 bridge 锚确实不可靠），
  结果 strict 变成**永久装饰**：锚修好之后，默认档仍然「改了也照跑」
  （红队复测：patch bridge → `bridge-diff=1` → `openIndex ok` → `OK`，exit=0）。
- **违反检测点**：`UmbraClassLoader.verifyOwnClassBytes` 的**锚健康探测**——
  用两次故意错值（`verifyLoader(bogus, 真实bridgeSha)` / `verifyLoader(真实loaderSha, bogus)`）
  判断两槽是否真的在拒；`strictAnchors = loaderSlotEnforced && bridgeSlotEnforced`。
  判据必须用**运行时自证**，不是构建期开关；`STRICT_NATIVE_VERIFY` 只是附加的构建期上限。
  锚不健康时打 `umbra-anchor-unhealthy=1 loader=<bool> bridge=<bool>`（机器可读、可计数）。
- **反例**：R67 关掉 strict → V28 红队默认档 patch bridge 仍 exit=0；
  反过来若只有构建期开关，锚一坏就会重演 R67（合法产物被误杀）。
- **规则**：静态开关会把「临时权宜」变成「永久装饰」；降级必须自带**自动恢复严格**的条件，
  且该条件要能被同一次启动验证。

---

## 自查清单（每次交付前）

1. 攻击方工具**先用一遍**（carve / indy_decode / fold / wm_crack）；
2. `-Xverify:all` + `--preset maximum` 跑通（含 `native.enabled` 的 experimental 边界说明）；
3. `VerifyDigest --selftest` 与 `VerifyLibraryKey --selftest` 都 `SELFTEST PASS`；
   `qa/verify/PATCH-ACCEPTANCE.md` 三例（legal 0 / patch loader 1 / patch bridge 1）复跑通过；
4. 报告里写清：这一版**哪个档位有秘密、哪个档位没有**；
5. 任何 skip / 降级 / 失败，在 stats 与日志里都能被第三方看见。
