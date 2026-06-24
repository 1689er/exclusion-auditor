"""CrowdStrike adapter tests. No falconpy and no live tenant required: the
normalizers are pure and pagination is exercised with a fake service."""

import pytest

from exclusion_auditor.adapters import crowdstrike as cs


# --- pattern kind inference ----------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (r"C:\Windows\Temp", "path"),
    (r"C:\*", "wildcard"),
    (r"C:\Users\*\AppData", "wildcard"),
    ("*.exe", "wildcard"),
    ("ps1", "extension"),
    ("badfile.exe", "extension"),
])
def test_infer_pattern_kind(value, expected):
    assert cs.infer_pattern_kind(value) == expected


# --- normalization --------------------------------------------------------

def test_normalize_ml_global():
    raw = {
        "id": "abc", "value": r"C:\Temp\*", "applied_globally": True,
        "created_by": "admin@x", "created_on": "2025-01-02T03:04:05Z",
        "comment": "build cache",
    }
    n = cs.normalize_ml(raw, tenant_cid="CID1")
    assert n.platform == "crowdstrike" and n.type == "ml"
    assert n.value == r"C:\Temp\*"
    assert n.pattern_kind == "wildcard"
    assert n.scope == "global"
    assert n.tenant_cid == "CID1"
    assert n.created_at == "2025-01-02T03:04:05Z"


def test_normalize_ml_scoped_with_group_names():
    raw = {
        "id": "x", "value": r"C:\App", "applied_globally": False,
        "groups": [{"id": "g1", "name": "Servers"}, {"id": "g2", "name": "DBs"}],
    }
    n = cs.normalize_ml(raw)
    assert n.scope == "host_group:Servers,DBs"


def test_normalize_ml_scoped_with_id_strings_and_name_map():
    raw = {"id": "x", "value": r"C:\App", "applied_globally": False,
           "groups": ["g1", "g2"]}
    n = cs.normalize_ml(raw, group_names={"g1": "Servers", "g2": "DBs"})
    assert n.scope == "host_group:Servers,DBs"


def test_scope_falls_back_to_id_when_unresolved():
    raw = {"applied_globally": False, "groups": ["g9"]}
    assert cs._scope(raw, {}) == "host_group:g9"


def test_normalize_ioa_uses_ifn_regex_and_is_process():
    raw = {
        "id": "i1", "name": "PS automation", "ifn_regex": r".*\\powershell\.exe",
        "cl_regex": ".*-enc.*", "pattern_name": "Suspicious PowerShell",
        "description": "approved in change CR-12",
        "applied_globally": True, "created_on": "2024-06-01T00:00:00Z",
    }
    n = cs.normalize_ioa(raw)
    assert n.type == "ioa"
    # IOA regex is normalized to a comparable glob path so process rules can match
    assert n.value == r"**\powershell.exe"
    assert n.pattern_kind == "wildcard"        # leading .* -> ** any-path prefix
    from exclusion_auditor.paths import base_name
    assert base_name(n.value) == "powershell.exe"   # EXCL-PROC-001 can now match
    # issue #6: comment is the admin description only, not synthesized metadata
    assert n.comment == "approved in change CR-12"


def test_normalize_ioa_without_description_has_empty_comment():
    # issue #6 regression: undocumented IOA must have empty comment so has_comment
    # is honest and the hygiene rule can fire.
    raw = {"id": "i2", "name": "x", "ifn_regex": ".*foo", "applied_globally": True}
    assert cs.normalize_ioa(raw).comment == ""


def test_ioa_regex_to_path_unescapes_and_globs():
    assert cs.ioa_regex_to_path(r".*\\Program Files\\Vendor\\app\.exe") == r"**\Program Files\Vendor\app.exe"
    assert cs.ioa_regex_to_path(r"^.*\\Windows\\Temp\\x\.exe$") == r"**\Windows\Temp\x.exe"
    # alternation groups are preserved as a wildcard segment
    assert cs.ioa_regex_to_path(r".*\\Users\\Public\\(a|b)\.exe") == r"**\Users\Public\(a|b).exe"


def test_ioa_pattern_kind_concrete_vs_wildcard():
    assert cs.ioa_pattern_kind(r"C:\Windows\System32\x.exe") == "process"
    assert cs.ioa_pattern_kind(r"**\powershell.exe") == "wildcard"
    assert cs.ioa_pattern_kind(r"**\Users\Public\(a|b).exe") == "wildcard"


def test_ioa_regex_cleans_whitespace_and_literal_metachars():
    # \s+ (regex whitespace) -> literal space; escaped metacharacters unescaped
    assert cs.ioa_regex_to_path(r".*\\Program\s+Files\\app\.exe") == r"**\Program Files\app.exe"
    assert cs.ioa_regex_to_path(r".*\\x\s+\(x86\)\\a\.exe") == r"**\x (x86)\a.exe"
    assert cs.ioa_regex_to_path(r".*\\u\+v\.exe") == r"**\u+v.exe"


def test_ioa_pattern_kind_literal_paren_is_not_wildcard():
    # a concrete path with a literal parenthesis must classify as process
    assert cs.ioa_pattern_kind(r"C:\Program Files (x86)\app.exe") == "process"
    # genuine alternation (|) is still a wildcard
    assert cs.ioa_pattern_kind(r"C:\x\(a|b).exe") == "wildcard"


# --- pagination (read-only) ----------------------------------------------

class FakeService:
    """Only exposes the two read methods the adapter is allowed to call."""

    def __init__(self):
        self.calls = []

    def query_exclusions(self, **kw):
        self.calls.append(("query", kw))
        if kw["offset"] == 0:
            return {"status_code": 200,
                    "body": {"resources": ["a", "b"],
                             "meta": {"pagination": {"total": 3}}}}
        return {"status_code": 200,
                "body": {"resources": ["c"], "meta": {"pagination": {"total": 3}}}}

    def get_exclusions(self, **kw):
        self.calls.append(("get", kw))
        return {"status_code": 200,
                "body": {"resources": [{"id": i, "value": i} for i in kw["ids"]]}}


def test_collect_all_paginates():
    svc = FakeService()
    resources = cs.collect_all(svc, page_size=2)
    assert [r["id"] for r in resources] == ["a", "b", "c"]
    # only read methods were ever called
    assert {c[0] for c in svc.calls} == {"query", "get"}


class FakeHostGroup:
    def __init__(self):
        self.calls = []

    def get_host_groups(self, **kw):
        self.calls.append(kw)
        names = {"g1": "Servers", "g2": "Workstations"}
        return {"status_code": 200,
                "body": {"resources": [{"id": i, "name": names.get(i, i)}
                                       for i in kw["ids"]]}}


def test_group_ids_by_cid():
    collected = [
        ("ml", None, {"groups": ["g1", {"id": "g2", "name": "x"}]}),
        ("ioa", "CID2", {"groups": ["g3"]}),
        ("ml", None, {"applied_globally": True}),
    ]
    out = cs.group_ids_by_cid(collected)
    assert out[None] == {"g1", "g2"}
    assert out["CID2"] == {"g3"}


def test_resolve_group_names_with_fake_service():
    hg = FakeHostGroup()
    mapping = cs.resolve_group_names(hg, {None: {"g1", "g2"}})
    assert mapping == {"g1": "Servers", "g2": "Workstations"}


def test_resolve_group_names_passes_member_cid():
    hg = FakeHostGroup()
    cs.resolve_group_names(hg, {"CID2": {"g1"}})
    assert hg.calls[0].get("member_cid") == "CID2"


def test_check_raises_on_api_error():
    bad = {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}}
    with pytest.raises(RuntimeError, match="access denied"):
        cs._check(bad, "query_exclusions")


def test_unknown_cloud_rejected():
    adapter = cs.CrowdStrikeAdapter({"cloud": "mars-1"})
    with pytest.raises(ValueError, match="unknown cloud"):
        adapter._resolve_base_url()
