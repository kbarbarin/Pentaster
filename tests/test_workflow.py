import pytest
from pentaster.workflow import Workflow, Step, load_workflow, validate_dag, execution_order

def make_wf(steps):
    return Workflow(name="t", steps=[Step(**s) for s in steps])

BASE = [
    {"id": "probe", "tool": "httpx", "image": "img", "args": ["-u", "{{target}}"], "parser": "httpx"},
    {"id": "content", "tool": "ffuf", "image": "img", "args": [], "parser": "ffuf", "depends_on": ["probe"]},
    {"id": "vulns", "tool": "nuclei", "image": "img", "args": [], "parser": "nuclei", "depends_on": ["probe"]},
]

def test_load_workflow_from_yaml(tmp_path):
    p = tmp_path / "wf.yaml"
    p.write_text(
        "name: web-basic\n"
        "steps:\n"
        "  - id: probe\n"
        "    tool: httpx\n"
        "    image: img\n"
        "    args: ['-u', '{{target}}']\n"
        "    parser: httpx\n"
    )
    wf = load_workflow(str(p))
    assert wf.name == "web-basic"
    assert wf.steps[0].id == "probe"
    assert wf.steps[0].depends_on == []

def test_validate_dag_missing_dependency_raises():
    wf = make_wf([
        {"id": "a", "tool": "x", "image": "img", "args": [], "parser": "httpx", "depends_on": ["ghost"]},
    ])
    with pytest.raises(ValueError, match="ghost"):
        validate_dag(wf)

def test_execution_order_layers():
    wf = make_wf(BASE)
    waves = execution_order(wf)
    assert [s.id for s in waves[0]] == ["probe"]
    assert {s.id for s in waves[1]} == {"content", "vulns"}

def test_execution_order_detects_cycle():
    wf = make_wf([
        {"id": "a", "tool": "x", "image": "img", "args": [], "parser": "httpx", "depends_on": ["b"]},
        {"id": "b", "tool": "x", "image": "img", "args": [], "parser": "httpx", "depends_on": ["a"]},
    ])
    with pytest.raises(ValueError, match="cycle"):
        execution_order(wf)

def test_execution_order_preserves_declared_order_in_wave():
    wf = make_wf(BASE)
    waves = execution_order(wf)
    # content déclaré avant vulns → même ordre dans la vague
    assert [s.id for s in waves[1]] == ["content", "vulns"]

def test_duplicate_step_id_rejected():
    import pytest
    wf = Workflow(name="w", steps=[
        Step(id="a", tool="httpx", image="img", args=[], parser="httpx"),
        Step(id="a", tool="nuclei", image="img", args=[], parser="nuclei"),
    ])
    with pytest.raises(ValueError, match="a"):
        validate_dag(wf)
