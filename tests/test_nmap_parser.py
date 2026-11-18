import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from dragon_guard.adapters.nmap_adapter import parse_nmap_xml, authorize, ScopeError


def test_parse_fixture():
    xml = (ROOT / "tests/fixtures/nmap_sample.xml").read_text()
    obs = parse_nmap_xml(xml, "exec-test", "nmap fixture")
    assert len(obs) == 1
    assert obs[0]["result"]["port"] == 22
    assert obs[0]["result"]["service"] == "ssh"
    assert obs[0]["schema_version"].startswith("dragon-guard/")


def test_scope_rejects_external():
    scope = {"allow_hosts": ["127.0.0.1", "localhost"], "allow_cidrs": ["127.0.0.0/8"]}
    assert authorize("127.0.0.1", scope) == "127.0.0.1"
    try:
        authorize("8.8.8.8", scope)
        assert False, "should reject"
    except ScopeError:
        pass


if __name__ == "__main__":
    test_parse_fixture()
    test_scope_rejects_external()
    print("ok")
