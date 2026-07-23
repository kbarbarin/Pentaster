import json
from pentaster.results import save_results, report_to_dict
from pentaster.engine import RunReport, StepOutcome
from pentaster.parsers import Finding

def make_report():
    f = Finding(tool="nuclei", target="t", type="vulnerability", severity="high", name="Bug", evidence="e", raw={"k": 1})
    return RunReport("web-basic", "http://localhost:3000", "s", "f", [StepOutcome("vulns", "nuclei", 0, [f])])

def test_report_to_dict_shape():
    d = report_to_dict(make_report())
    assert d["workflow"] == "web-basic"
    assert d["findings_count"] == 1
    assert d["outcomes"][0]["findings"][0]["name"] == "Bug"

def test_save_results_writes_file(tmp_path):
    path = save_results(make_report(), str(tmp_path / "run1"))
    assert path.endswith("results.json")
    data = json.loads(open(path).read())
    assert data["target"] == "http://localhost:3000"
    assert data["outcomes"][0]["findings"][0]["severity"] == "high"
