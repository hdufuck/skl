# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root, or
- **`CONTEXT-MAP.md`** at the repo root if it exists: it points at one `CONTEXT.md` per context. Read each one relevant to the topic.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in. In multi-context repos, also check `src/<context>/docs/adr/` for context-scoped decisions.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates them lazily when terms or decisions actually get resolved.

## File structure

Single-context repo (this repo):

```text
/
├── CONTEXT.md                    ← 领域词汇表（本仓库特有语言）
├── AGENTS.md
├── docs/
│   ├── adr/                      ← 架构决定
│   │   ├── 0001-证据只能来自一次真实签到窗口.md
│   │   ├── 0002-本机探针与浏览器取参的取舍.md
│   │   └── 0003-浏览器自称与真实平台自洽.md
│   ├── agents/                   ← 本 skill 的输出
│   ├── api.md
│   └── signin-probe.md
├── cmd/signinprobe/              ← 一次性签到探针（CLI）
├── internal/
│   ├── probe/                    ← 阶梯、判读、读回、报告
│   └── chromecaptcha/            ← 浏览器取人机凭证真值
├── pkg/                          ← 面向外部调用方的公开 API
└── *.go                          ← 根包 skl：会话、鉴权、API 封装
```

Multi-context repo (presence of `CONTEXT-MAP.md` at the root):

```text
/
├── CONTEXT-MAP.md
├── docs/adr/                          ← system-wide decisions
└── src/
    ├── ordering/
    │   ├── CONTEXT.md
    │   └── docs/adr/                  ← context-specific decisions
    └── billing/
        ├── CONTEXT.md
        └── docs/adr/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
