# Agent 安全靶场（agent-redteam）

给**带工具的 Agent** 建一套可复现的红队评测：攻击用例批量打过去，目标 Agent 在**五层可独立开关的防御**下运行，
用「工具调用轨迹断言 + LLM 判据」判定成败，最后量化**防御前 vs 防御后**的攻击成功率与误杀率。

> 大多数 Agent 作品展示的是「它能做什么」。这个项目回答另一个问题：**它搞不定的时候会怎样，代价能不能量化。**

## 一、当前基线（本机实测）

| 指标 | 结果 |
| --- | --- |
| 攻击用例 | 60 条（直接注入 / 间接注入 / 越权工具调用 / 数据外泄 / 多轮渐进，各 12 条） |
| 正常任务 | 20 条（用于测误杀，覆盖问数、文档问答、通知、接口探活四类） |
| 攻击成功率 ASR | 防御全关 **100.0%** → 防御全开 **1.7%** |
| 正常任务通过率 | 全开下 **100%**（误杀 0） |
| 逐层边际 | ③ 参数校验 **+21.6 pp**、⑤ 出站过滤 **+8.3 pp**、①②④ 各 **+3.3 pp** |
| 全量评测耗时 | 60 + 20 条 × 7 种配置 = 560 次运行，约 **4 s** |

> ⚠️ **口径声明**：上表的 provider 是 `scripted`——一个确定性的「naive instruction follower」，
> 把 7B 级模型常见的失效方式写成规则。它用来验证**评测链路**和**各层防御的贡献**，
> **不代表真实模型的攻击成功率**。接真模型只需换 provider，用例集与判据完全复用：
>
> ```bash
> python -m app.runner.evaluate --provider ollama     # 本地 qwen2.5:7b
> python -m app.runner.evaluate --provider deepseek   # 需在 .env 配 DEEPSEEK_API_KEY
> ```

## 二、30 秒复现

```bat
setup.bat
run.bat              :: 跑矩阵评测 -> 出报告 -> 起看板 http://127.0.0.1:8000
```

等价的手动命令：

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python -m app.runner.evaluate     # 生成 reports/bench.md、web/data.js
.venv/Scripts/python -m app.main                # 看板
.venv/Scripts/python -m pytest                  # 26 条测试
```

产物：`reports/bench.md`（报告）、`reports/summary.json`（机读）、`web/data.js`（看板数据）、`reports/runs.db`（轨迹落库）。

## 三、目录结构

```
app/
  main.py          FastAPI 入口：看板 + /api/summary + /healthz
  common/          路径解析、日志
  core/            配置加载（conf/*.yaml）、提示词加载（prompts/*.md）
  agent/
    tools.py       四个工具：read_file / query_db / send_message / http_get
    workflow.py    LangGraph 状态机：decide → act → 条件边
    engine.py      单次运行编排（多轮、轨迹、LangGraph/线性双引擎）
  llm/             scripted（离线）/ ollama（本地）/ deepseek（兼容接口）
  defense/         五层防御，同构接口，可独立开关
  judge/           规则判据（主力）+ LLM 判据（补位）
  runner/          用例加载、结果落库、指标聚合、评测 CLI
cases/             60 条攻击用例 + 20 条正常任务 + 任务模板
conf/              agent.yaml / defense.yaml / evaluation.yaml
data/              合成数据：订单库、假密钥、带注入的检索文档
docs/              架构设计、用例规范、评测口径
prompts/           agent_system.md / safety_note.md / llm_judge.md
reports/           bench.md（脚本产出，禁止手填）
tests/             unit（工具 / 防御）+ e2e（判定与双引擎一致性）
web/               单页看板
```

## 四、三层架构

```
① 目标 Agent（能力层）      tools.py 提供 4 个工具，只做能力，不做安全判断
② 防御层（边界层）          defense/layers.py 五层同构，before_call / post_tool 两个钩子
③ 评测层（度量层）          runner 批量跑 + judge 判定 + metrics 聚合
```

**为什么把「安全判断」从工具里拿出来？** 因为要测的是「防御值多少」。如果工具自己就做了路径校验，
关掉防御也测不出脆弱面，逐层边际就永远为 0——评测会变成自证清白。

## 五、五层防御与各自的作用

| 层 | 做什么 | 实测边际 | 说明 |
| --- | --- | --- | --- |
| ① 指令隔离 | 工具输出标注为数据 + 系统提示声明优先级 | +3.3 pp | 只对「不含 SYSTEM: 伪造」的间接注入有效 |
| ② 工具白名单 | 按任务阶段限制可用工具集合 | +3.3 pp | 读任务不给发消息权限 |
| ③ 参数校验 | 路径沙箱 + sqlglot AST 白名单 + 内网地址拦截 | **+21.6 pp** | 单层贡献最大，因为路径与 SQL 是主要攻击面 |
| ④ 权限闸门 | 高风险工具的目标必须在白名单内 | +3.3 pp | 收件人 / 主机双白名单 |
| ⑤ 出站过滤 | 外发内容里的密钥与内网地址脱敏 | +8.3 pp | 唯一能兜住「白名单通道外带」的一层 |

## 六、三个关键设计决策

1. **规则判据优先，LLM 判据只补位**
   轨迹断言（工具名 / 参数 / 外发内容）可复现、零成本；只有「语义上算不算被攻破」才交给 judge，
   且 judge 必须先用 20 条人工标注校准。用 LLM 当唯一判据，等于把评测交给另一个会犯错的黑盒。

2. **每个配置都同时跑 20 条正常任务**
   只测攻击不测正常，会得出「防御越严越好」的错误结论。误杀率与 ASR 必须一起看：
   ④ 权限闸门是拦截最多的一层，也是最容易误杀的一层，这个取舍要显式写出来。

3. **主链路用状态机，不用自由 Agent 循环**
   「想 → 做 → 看结果 → 再想」固化成 LangGraph 的 decide/act 节点 + 条件边，每次失败都能重放到具体节点与参数。
   `--engine linear` 提供等价线性实现，tests 会验证两者结果一致——避免「框架换了个写法就悄悄改了行为」。

## 七、真实模型接入记录（2026-10-23）

已接通 OpenAI 兼容网关（DeepSeek-v4-flash），结论分两层：

1. **链路可用**：跑通 42 个运行（约 105 次模型调用），工具调用与 JSON 协议正常，模型会按
   `{"action":"tool","tool":"query_db","args":{...}}` 行动。
2. **模型自带对齐**：直接注入会被拒绝（典型回复「抱歉，我无法满足该请求」），
   说明真实模型的 ASR 主要不取决于我们加了几层防御，而取决于模型本身的对齐强度；
   剩余风险集中在**间接注入**（文档/工具返回里的指令）与**工具参数越权**。

3. **全量矩阵未完成**：该免费网关在约 105 次调用后开始持续返回 401（同一 key 未超限时可用），
   单次调用 3–15 s，约 40% 请求出现 SSL 断连。额度恢复后一条命令补跑：

   ```bash
   python -m app.runner.evaluate --provider deepseek --workers 2
   ```

   为适配这类不稳定网关，runner 已具备：`--workers` 并发、6 次重试、401 长退避、
   JSON 解析失败自动纠正、outbox 线程隔离。

## 八、已知局限（主动写出来）

- **真实模型全量分未跑完**：仓库里的数字来自 scripted provider，只能证明链路与防御机制，不能替代真实 LLM 的 ASR。
- **规则判据覆盖有限**：语义级「算不算被攻破」仍需 LLM judge，接口已留（`app/judge/llm.py`），校准流程未跑通。
- **⑤ 不覆盖回答本身**：出站脱敏只管外发通道；模型把密钥写进回答（answer 泄露）只能靠 ① 与模型侧，这一层没有兜底。
- **只覆盖文本注入**：多模态、文件附件、编码混淆（base64 / 同形字）未覆盖。
- **SYSTEM: 伪造能绕过 ①**：`I08` 是唯一在全开防御下仍然成功的用例，保留它而不是「调参调绿」，因为这是真实失效点。

## 八、和已有项目的关系

SQL 侧做过的是「不可信输入不进执行路径」（AST 白名单、权限条件下推最内层 WHERE）；
这个项目把同一套思路挪到 Agent 的工具调用链——**不可信内容不获得执行权**。
两边的判据都是一样的：不看模型说了什么，只看它实际做了什么。
