from pathlib import Path
import tempfile
from jsxray.engine import JSXRayEngine
from jsxray.models.finding import FindingType


def test_golden_specification_case():
    golden_code = """
const API="https://api.example.com";

fetch(API+"/users/"+userId,{
  method:"GET",
  headers:{
    Authorization:"Bearer "+token
  }
});
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as tf:
        tf.write(golden_code)
        tf_name = tf.name

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as out_tf:
        out_report = out_tf.name

    engine = JSXRayEngine(js_path=tf_name, output_file=out_report)
    result = engine.run()

    # 1. API Host Check
    hosts = [f.value for f in result.findings if f.type == FindingType.API_HOST]
    assert "api.example.com" in hosts

    # 2. Endpoint Check
    endpoints = [f.normalized_value for f in result.findings if f.type == FindingType.API_ENDPOINT]
    assert any("https://api.example.com/users/{userId}" in ep or "https://api.example.com/users/{param}" in ep or "https://api.example.com/users" in ep for ep in endpoints)

    # 3. Parameter Check
    params = [f.value for f in result.findings if f.type == FindingType.PARAMETER]
    assert "userId" in params or "param" in params

    # 4. Authentication Check
    auths = [f.value for f in result.findings if f.type == FindingType.AUTHENTICATION]
    assert any("Bearer" in a for a in auths)

    # 5. HTML Report was generated
    assert Path(out_report).exists()
    assert Path(out_report).stat().st_size > 500
