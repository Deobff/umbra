# Umbra 交付文档索引

> 这份索引把本轮对抗赛产生的所有文档、工具与结论串起来。
> **先读哪一篇，取决于你想知道什么。**

## 我想知道「这套东西到底防住了什么」

→ [GAME-REPORT.md](GAME-REPORT.md)（173 行）

- §1 最终比分（守 14 : 攻 19）
- §2 全部路径一览（12+ 条，逐条结论）
- §7 **诚实清单**（已修复 / 成立但不可修 / 守住了，三分类）
- 结尾：**「防离线，不防进程内」**——这份报告最重要的一句话

## 我想知道「改代码时不能违反什么」

→ [SECURITY-INVARIANTS.md](SECURITY-INVARIANTS.md)（I1–I13）

每条含：来源（哪一轮哪个漏洞）、违反检测点（代码里在哪拦）、反例（本场真实数字）。
**末尾有交付前自查清单。**

## 我想知道「java2c 能不能用」

→ [JAVA2C-STATUS.md](JAVA2C-STATUS.md)

- §0.2 V27/V28 已修复（默认档与实验档都验证）
- §0.1 已知限制（含强度降级的准确描述）
- **`native.enabled` 默认关闭，experimental**

## 我想验证某个安全结论（不信文档）

→ `qa/verify/`

| 工具 | 验证什么 | 三态 |
|---|---|---|
| `VerifyDigest` | `keyedDigest` 与类完整性 | 0 MATCH / 1 MISMATCH / 2 BAD_INPUT |
| `VerifyLibraryKey` | libraryMode 无 key 打不开 | 0 OPENED / 1 REJECTED / 2 BAD_INPUT |
| `RewriteClass` | V27/V28 锚定（patch 后被拒） | 见 `PATCH-ACCEPTANCE.md` |

**三个都能 `--selftest`，且坏输入有明确退出码。**

## 我想知道每一分的判决依据

→ `qa/game/SCOREBOARD.md`（900+ 行）

含每一次判分的证据、裁判理由、以及被拒绝的申分（及拒绝原因）。

## 三个必须记住的数字

```
守 14 : 攻 19        （33 / 50，未达 50 分结束条件）
1,832 / 1,832        （旧 seed 绑定产物 CP 全解 —— R10 fail-closed 改动的必要性证据）
3 / 3                （默认档稳定性：同一 jar 连跑三次 exit=0）
```

## 一句话

> 这轮工作的产出不是「一个更安全的混淆器」，
> 而是「**一份知道自己哪里不安全、并且能证明自己的描述是对的**的混淆器」。