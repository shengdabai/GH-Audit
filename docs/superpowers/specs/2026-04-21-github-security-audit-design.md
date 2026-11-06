# gh-audit: GitHub 仓库安全审计工具 设计文档

**日期：** 2026-04-21  
**状态：** 已确认，待实施  
**定位：** 个人/小团队 CLI 工具

---

## 1. 目标

构建一个命令行工具，对 GitHub 仓库（公开或私有）进行系统化安全检查，输出详细风险评估报告。工具定位为只读审计平台：不修改仓库，不执行目标代码，不把原始 secret 写入任何文件。

---

## 2. 用户画像

- **个人开发者或小团队**
- 扫描自己负责的仓库，或对感兴趣的公开仓库做审计
- 希望零配置可运行，有外部工具时自动增强

---

## 3. 整体架构

```
gh-audit (CLI 入口)
    │
    ├── 配置层 (config.py)
    │     ├── PAT / GitHub App 凭证管理
    │     └── 扫描策略配置
    │
    ├── 资产发现层 (discovery.py)
    │     ├── Org 下所有仓库列举
    │     ├── 分支 / Tag / Release 枚举
    │     └── 仓库克隆到临时目录（扫完即删）
    │
    ├── 检测模块层 (scanners/)
    │     ├── secrets.py      — Python 内置 + 可选 Gitleaks/TruffleHog
    │     ├── pii.py          — Presidio + 中文本地化规则
    │     ├── sast.py         — 可选 Semgrep/Bandit
    │     ├── sca.py          — 可选 OSV-Scanner（无则降级 API 模式）
    │     ├── iac.py          — 可选 Trivy/Checkov
    │     └── governance.py   — 纯 GitHub API，零外部依赖
    │
    ├── 结果归一化层 (normalizer.py)
    │     ├── 统一 Finding 数据结构
    │     ├── 证据脱敏（原始 secret 不落盘）
    │     └── 指纹去重
    │
    ├── 风险评分引擎 (scorer.py)
    │     └── 五维评分：Severity × Confidence × Exposure × Criticality × BlastRadius
    │
    └── 报告引擎 (reporters/)
          ├── terminal.py     — Rich 彩色终端输出
          ├── json_report.py  — 结构化 JSON
          └── html_report.py  — 自包含静态 HTML
```

**关键约束：**
- 每个 scanner 统一接口：`scan(repo_path, config) -> List[Finding]`
- 外部工具通过 `shutil.which()` 检测，存在则调用，不存在则降级
- 克隆到 `/tmp` 临时目录，扫完 `shutil.rmtree` 清理
- 完整 secret 值永远不写入报告文件

---

## 4. 核心数据结构

```python
@dataclass
class Finding:
    # 身份
    finding_id: str           # UUID
    fingerprint: str          # sha256(category+file+line+snippet)，用于去重

    # 位置
    repo: str                 # org/repo-name
    branch: str
    commit_sha: str
    file_path: str
    line_start: int
    line_end: int

    # 分类
    category: str             # secrets / pii / sast / sca / iac / governance
    rule_id: str
    title: str

    # 评分
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "likely", "possible"]

    # 证据（脱敏）
    evidence_redacted: str    # 如 "AWS_KEY=AKIA****...****XXXX"

    # 建议
    recommendation: str
    standard_mapping: list[str]  # 如 ["OWASP-A02", "CWE-798"]

    # 元数据
    scanner: str              # "gitleaks" / "presidio" / "builtin"
    discovered_at: datetime
    status: Literal["open", "suppressed", "fixed"]
```

**脱敏规则：**
- Secret 类：保留前 4 位 + `****` + 后 4 位
- 邮箱：`u***@domain.com`
- 手机：`138****8888`
- 身份证：`110***********1234`

**本地持久化：**
- 结果存 `~/.gh-audit/results/<org>/<repo>/<timestamp>.json`
- 支持基线对比：新发现 vs 上次扫描（`--diff` 模式）

---

## 5. 检测模块详细设计

### 5.1 Secrets 模块

**内置规则（Python 自实现，零依赖）：**
- 高熵字符串检测（Shannon 熵 > 4.5，字符串长度 ≥ 20）
- 常见前缀模式：`AKIA`（AWS）、`ghp_`/`ghs_`（GitHub）、`sk-`（OpenAI）等 50+ 模式
- 文件名黑名单：`.env`、`*.pem`、`id_rsa`、`credentials*`
- Git 历史回溯（默认最近 100 commits，`--depth` 可配置）

**外部工具增强（可选）：**
- Gitleaks：150+ 服务 Secret 规则
- TruffleHog：格式验证模式（不主动调用第三方 API）

### 5.2 PII 模块

**Presidio（英文 PII）：** 邮箱、信用卡、IP、US Phone

**中文本地化规则（内置 Regex）：**
- 手机号：`1[3-9]\d{9}`
- 身份证：18 位 + Luhn 校验
- 统一社会信用代码：18 位特定格式
- 银行卡：Luhn 校验
- 护照：`[EG]\d{8}`

**重点扫描文件类型：** `.csv`、`.json`、`.log`、`.sql`、`.xlsx`

### 5.3 Governance 模块（纯 GitHub API）

每项输出 pass / fail / warn：

- 默认分支保护是否启用
- PR 必须审核（require reviews）
- Secret scanning 是否开启
- Dependabot 是否开启
- `SECURITY.md` 是否存在
- `CODEOWNERS` 是否存在
- Actions 权限是否限制为 `read-all`

### 5.4 SAST / SCA / IaC（可选增强）

| 模块 | 首选工具 | 降级行为 |
|------|---------|---------|
| SAST | Semgrep | Bandit（Python only） |
| SCA  | OSV-Scanner | 解析 requirements.txt / package-lock.json 对比 OSV API |
| IaC  | Trivy | Checkov |

无任何工具时输出：`[SKIP] 模块未启用，请安装 semgrep 以激活`

---

## 6. CLI 接口设计

```bash
# 扫描单个仓库
gh-audit scan owner/repo

# 扫描整个组织
gh-audit scan --org myorg

# 指定分支
gh-audit scan owner/repo --branch main

# 扫历史提交
gh-audit scan owner/repo --history --depth 200

# 指定启用的模块
gh-audit scan owner/repo --modules secrets,pii,governance

# 输出格式（多选）
gh-audit scan owner/repo --output terminal,json,html

# 只报 high 及以上
gh-audit scan owner/repo --min-severity high

# 基线对比（只报新增问题）
gh-audit scan owner/repo --diff

# 查看工具依赖状态
gh-audit doctor

# 查看历史扫描结果
gh-audit history owner/repo

# 压制误报
gh-audit suppress <finding_id> --reason "test data" --expires 30d
```

**认证配置：**
```bash
export GITHUB_TOKEN=ghp_xxxxx
# 或
gh-audit config set token ghp_xxxxx
```

**`gh-audit doctor` 示例输出：**
```
✓ GitHub token        valid (rate limit: 4987/5000)
✓ secrets module      builtin + gitleaks v8.18.0
✓ pii module          presidio 2.2.35
✗ sast module         semgrep not found (pip install semgrep)
✓ sca module          osv-scanner fallback (API mode)
✗ iac module          trivy not found (brew install trivy)
✓ governance module   GitHub API ready
```

---

## 7. 报告输出

### 终端输出示例

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 gh-audit scan: myorg/backend  (47 files, 312 commits)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] AWS Access Key exposed
  File: config/deploy.yml:23
  Commit: a3f9d12 (2026-03-15)
  Evidence: AKIA****...****WXYZ
  → Rotate immediately, use GitHub Secrets instead

[HIGH] 手机号出现在测试数据文件
  File: tests/fixtures/users.csv:1-50
  Evidence: 138****8888 (×47 rows)
  → Replace with faker-generated data

[MEDIUM] Branch protection not enabled
  Repo: myorg/backend (default branch: main)
  → Enable in Settings → Branches

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Summary: 3 critical · 5 high · 12 medium · 8 low
 Report:  ~/.gh-audit/results/myorg/backend/20260421.html
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 8. 项目目录结构

```
gh-audit/
├── gh_audit/
│   ├── __init__.py
│   ├── cli.py               # Click CLI 入口
│   ├── config.py            # 配置管理
│   ├── discovery.py         # 资产发现 & 克隆
│   ├── normalizer.py        # Finding 归一化 & 去重
│   ├── scorer.py            # 五维风险评分
│   ├── models.py            # Finding dataclass
│   ├── scanners/
│   │   ├── base.py          # BaseScanner 抽象类
│   │   ├── secrets.py
│   │   ├── pii.py
│   │   ├── sast.py
│   │   ├── sca.py
│   │   ├── iac.py
│   │   └── governance.py
│   └── reporters/
│       ├── terminal.py
│       ├── json_report.py
│       └── html_report.py
├── tests/
│   ├── fixtures/            # 无害测试数据
│   └── test_scanners/
├── pyproject.toml
└── README.md
```

---

## 9. 安全设计原则

1. **只读**：不修改目标仓库任何内容
2. **不执行目标代码**：不运行 build / test / install 脚本
3. **证据最小化**：Secret 脱敏后才落盘，原始值不存储
4. **临时目录隔离**：克隆到 `/tmp`，扫完立即删除
5. **最小权限**：PAT 只需 `repo:read`（私有仓库）或无 token（公开仓库）

---

## 10. 依赖清单

**必需（pip install 自动安装）：**
- `click` — CLI 框架
- `rich` — 终端彩色输出
- `PyGithub` — GitHub API 客户端
- `gitpython` — Git 历史扫描
- `presidio-analyzer` — PII 检测
- `requests` — OSV API 降级模式

**可选（用户自行安装以增强检测能力）：**
- `gitleaks` — Secret 扫描增强
- `semgrep` — SAST
- `osv-scanner` — SCA
- `trivy` — IaC / 容器风险
