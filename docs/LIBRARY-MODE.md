# Library 模式设计（把库 jar 也封起来）

> 现状：类加密需要一个入口点（`Main-Class` / `main(String[])`）注入 trampoline。
> **没有入口点的库 jar 结构上拿不到类加密**——R10 起改为构建失败，不再静默放过。
> 本文是把它变成「可支持」的设计。

## 1. 问题

类加密的启动链是：`main` trampoline → 装载 loader 类 → 解密 index → `defineClass` 每个业务类。
库 jar 没有 `main`，这条链没有起点，所以整包只能保持明文。

## 2. 方案：显式 bootstrap 契约

库的宿主应用必须**主动**用我们的 loader 打开归档。产品形态：

```java
// 宿主侧（只需一行）
ClassLoader lib = io.umbra.bootstrap.UmbraLibrary.open(new File("lib.jar"));
Class<?> api = lib.loadClass("com.acme.Library");   // 之后一切走这个 loader
```

### 归档内的布局

| 部分 | 状态 | 说明 |
|---|---|---|
| `io/umbra/bootstrap/UmbraLibrary.class` | **明文**（唯一） | 薄壳：读 jar、实例化 loader、返回 `ClassLoader` |
| loader / crypto / handler / connection | 密封 | 由 bootstrap 先 define（它自己解 index） |
| 业务类 | 密封 | 与现有流程一致 |

关键：**bootstrap 类必须自包含**（只依赖 JDK），不能引业务类，也不能引加密层——它是唯一的明文入口。

## 3. 实施步骤

1. **bootstrap 模板**（新文件 `core/runtime/UmbraLibraryBootstrap.java`）：
   - `public static ClassLoader open(File jar) throws IOException`；
   - 用 `ZipFile` 读 index 条目、用内置 KDF 解 index（复用 `UmbraCrypto` 的公开静态方法）；
   - 通过 `defineClass` 装载 loader 类，再把 loader 实例化；
   - 返回那个 loader（它已经能解业务类）。
2. **ClassEncryptionPass.libraryMode**：
   - 不注入 trampoline；
   - 保留 bootstrap 为明文条目；
   - 其余照常密封；
   - 构建期断言：bootstrap 不含对业务类的引用（ASM 扫描常量池）。
3. **入口点判定**：`main` 缺失时，若 `classEncryption.libraryMode=true` 则走本模式，否则维持 R10 的 fail-closed。
4. **文档**：`docs/OPTIONS.md` 增 `classEncryption.libraryMode`，README 给宿主接入示例。

## 4. 安全边界（要写进文档，不要吹）

- bootstrap 是明文，攻击者能看到它与 loader 的接口——**但它不持有密钥**：
  index 的解密钥仍由 native keyRoot 派生（native-bound 时），bootstrap 只是把它读出来交给 loader；
- 因此「拿到 bootstrap + 库 jar」仍然解不开业务类（与 V3 的离线判据一致）；
- 若宿主在**不可信环境**里调用，攻击者可以挂钩 `UmbraLibrary.open` 的返回值拿到 loader 实例——
  这是库模式的固有弱点（宿主主动交出 loader），与 jar 本身的保护强度无关；文档必须写明。

## 5. 验收

1. 造一个无 `main` 的库 jar（2 个公开类 + 1 个内部类），`--set classEncryption.libraryMode=true` 保护；
2. 宿主测试程序：`UmbraLibrary.open(...)` → `loadClass` → 调用方法 → 结果正确；
3. 归档里**只有 1 个明文 class**（bootstrap），其余密封；
4. 攻击者用 V3 的离线判据打：拿 bootstrap + 归档密文，**解不出业务类明文**；
5. `--verify` 通过。

## 6. 风险

- bootstrap 里若不小心引用了 `UmbraCrypto`（密封类），会 `NoClassDefFoundError`——必须构建期断言；
- 宿主忘记用 loader → `ClassNotFoundException`，错误信息要能指向文档；
- Mixin / 反射框架可能需要额外适配（先不做）。
## 7. 实测（Lead 独立复验）

输入：`build-lib/lib.jar`（1 个业务类 `libtest.Util`，无 `main`）。

```powershell
java -jar build-libdist\dist\umbra.jar -i build-lib\lib.jar -o build-lib\sealed.jar `
  --preset maximum --seed 23303 --set classEncryption.libraryMode=true --set renamer.enabled=false

[INFO] class-encryption: encrypted 45 classes and 1 resources, entries=55,
       masterBinding=native(native-root+comment)
```

宿主：
```java
ClassLoader lib = UmbraLibrary.open(new File(args[0]));
Object v = lib.loadClass("libtest.Util").getMethod("name").invoke(null);
```
```
host exit=0  out=SEALED-LIB-OK lib-util
entries=55  plaintextClasses=6
  n0luLZmll19Fxjf.class      ← loader
  n0luuzl7fhdBHxXhl.class    ← cipher
  n0luKkFTWt3GDep.class      ← handler
  n0luHVKzejawckh.class      ← connection
  n0luNL5OYVaNiOE.class      ← native loader
  io/umbra/bootstrap/UmbraLibrary.class
```
业务类 `libtest/Util` **不在明文列表里**（已成密封 payload）。

### 与设计的一处偏差（如实记录）
设计写的是「只留 1 个明文类」，实测是 **6 个**：bootstrap 链（loader / cipher / handler / connection / native loader）必须在明文里，否则 bootstrap 自己起不来。
bootstrap 本身仍是唯一**业务方可见**的入口；另外 5 个是 Umbra 自己的运行时，不承载业务逻辑。
## 8. module-info 库（实测通过）

```powershell
java -jar build-r12\dist\umbra.jar -i lib\asm-9.11.jar -o asm-lib.jar `
  --preset maximum --seed 23303 --set classEncryption.libraryMode=true `
  --set classEncryption.nativeKey.fallback=true
```
```
entries=1840  plaintextClasses=6
  n0luLZmll19Fxjf.class / n0luuzl7fhdBHxXhl.class / n0luKkFTWt3GDep.class
  n0luHVKzejawckh.class / io/umbra/bootstrap/UmbraLibrary.class
  module-info.class          ← 按设计保留明文
其余 1833 个业务类全部密封
```

引擎门的放宽（`UmbraEngine`）：库模式下 `module-info` 不再整档关闭，而是「module-info 明文 + 其余密封」。

## 9. 一条硬约束：库模式拿不到 native key root

`NativeGuardPass` 需要入口点注入 guard；库 jar 没有入口 → **没有 keyRoot**。
因此 `--preset maximum`（默认 `nativeKey=true`、`fallback=false`）在库模式下会 **fail-closed**：
```
IllegalStateException: classEncryption.nativeKey=true but the native key binding could not be
established ... (set classEncryption.nativeKey.fallback=true to accept the seed fallback explicitly)
```

要出库产物必须显式接受 seed 绑定：`--set classEncryption.nativeKey.fallback=true`。
**这是真实的安全降级**，文档必须写明：库模式的归档密钥绑定在 seed 上，不像可执行 jar 那样绑 native 根。
## 10. nested 布局（Spring Boot / WAR）评估结论：不密封，但会明确报错

实测（自造 `BOOT-INF/classes/nested/Util.class` 的 boot-like jar）：
```
java -jar build-r12\dist\umbra.jar -i build-nested\boot-like.jar -o sealed-nested.jar `
  --preset maximum --seed 23303

exit=1
layout: class encryption cannot seal a spring-boot layout with spring-boot;
refusing to produce an archive whose class encryption is silently OFF
artifact=False
```

### 为什么不做
nested 布局里类在 `BOOT-INF/classes/` 下，由 Spring Boot 的 `LaunchedURLClassLoader` 加载。
要在那里密封，必须替换/包装 boot loader 的类解析链——那是对宿主框架的内部集成，
不同 boot 版本实现不同（2.x vs 3.x），属于**高风险、低确定性**的工作，不在当前路线里。

### 当前行为（正确）
- `maximum` + nested → **构建失败**并给出原因（不再产出「看起来混淆过、实际类明文」的归档）；
- 用户确需产出时必须显式 `classEncryption.allowSkip=true`，且 stats 里有 `layout.classEncryptionSkipped=1` + 原因。

### 如果以后要做
最小可行路径是：把整个 `BOOT-INF/classes` 子树当作一个「密封库」，由我们自己的 `UmbraLibrary.open` 加载，
再用一个 boot 兼容的 `LaunchedURLClassLoader` 子类桥接。工作量在两个 loader 的互操作，不在密码学。