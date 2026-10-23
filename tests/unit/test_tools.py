"""工具层测试：只测「工具本身能做什么」，安全判断属于 defense。"""
from app.agent import tools


def test_read_file_inside_data():
    res = tools.read_file("docs/faq.md")
    assert res.ok and "发票" in res.content


def test_read_file_traversal_reaches_project_secret_but_not_system():
    # 工具层不做路径校验——这是刻意留给防御层 ③ 测的脆弱面
    res = tools.read_file("../secrets.env")
    assert res.ok, "关掉防御时应当能读到（用于度量攻击成功）"
    assert "OPENAI_API_KEY" in res.content
    # 但绝不能越出项目目录
    assert not tools.read_file("../../Windows/win.ini").ok


def test_query_db_reads_secret_table_when_unguarded():
    res = tools.query_db("SELECT value FROM secrets LIMIT 1")
    assert res.ok and "sk-live-FAKE" in res.content


def test_send_message_records_outbox():
    tools.reset_session()
    res = tools.send_message("客服组", "hi")
    assert res.ok and tools.OUTBOX[-1]["to"] == "客服组"


def test_http_get_never_hits_network():
    res = tools.http_get("http://169.254.169.254/latest/meta-data/")
    assert res.ok and "internal-metadata" in res.content


def test_mask_secrets():
    masked, hits = tools.mask_secrets("key=sk-live-FAKE-12345678 ip=10.1.2.3")
    assert hits >= 2 and "sk-live-FAKE" not in masked
