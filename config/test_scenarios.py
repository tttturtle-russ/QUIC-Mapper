import io
import pytest
from config.scenarios import load_scenario, ScenarioError


def test_load_simple_scenario():
    scenario_content = """[general]
name = trivial_tls13
role = client
tls_version = tls13
input_vocabulary = TLS13ClientHello, TLSFinished, TLSApplicationData, TLSCloseNotify
"""
    input_file = io.StringIO(scenario_content)
    scenario = load_scenario(input_file, [])

    assert scenario.name == "trivial_tls13"
    assert len(scenario.input_vocabulary) == 4
    assert "TLS13ClientHello" in scenario.input_vocabulary
    assert "TLSApplicationData" in scenario.input_vocabulary
    assert not scenario.interesting_paths
    assert not scenario.happy_paths


def test_load_scenario():
    scenario_content = """[general]
name = tls13
role = client
tls_version = tls13
input_vocabulary = TLS13ClientHello, TLSChangeCipherSpec, TLS13EmptyCertificate, TLS13Certificate_{crypto_material_name}, TLSCertificateVerify, TLSInvalidCertificateVerify, TLSFinished, TLSApplicationData, TLSApplicationDataEmpty, TLSCloseNotify, NoRenegotiation
happy_paths = standard_happy_path, empty_cert_happy_path, client_cert_happy_path
interesting_paths = path1, path2


[path1]
path = TLS13ClientHello, TLS13ClientHello

[path2]
parameter = crypto_material_name
path = TLS13ClientHello, TLS13Certificate_{crypto_material_name}, TLS13ClientHello

[standard_happy_path]
path = TLS13ClientHello, TLSFinished, TLSApplicationData
answers = , TLSFinished,

[empty_cert_happy_path]
path = TLS13ClientHello, TLS13EmptyCertificate, TLSFinished, TLSApplicationData
answers = , , TLSFinished,

[client_cert_happy_path]
path = TLS13ClientHello, TLS13Certificate_Valid, TLSCertificateVerify, TLSFinished, TLSApplicationData
answers = , , , TLSFinished,
"""
    input_file = io.StringIO(scenario_content)
    scenario = load_scenario(input_file, ["Valid", "Invalid"])

    assert scenario.name == "tls13"

    assert len(scenario.input_vocabulary) == 12
    assert "TLS13ClientHello" in scenario.input_vocabulary
    assert "TLS13Certificate_Valid" in scenario.input_vocabulary
    assert "TLS13Certificate_Invalid" in scenario.input_vocabulary

    assert len(scenario.interesting_paths) == 6
    assert [
        "TLS13ClientHello",
        "TLS13ClientHello",
    ] in scenario.interesting_paths
    assert [
        "TLS13ClientHello",
        "TLS13Certificate_Valid",
        "TLS13ClientHello",
    ] in scenario.interesting_paths
    assert [
        "TLS13ClientHello",
        "TLSFinished",
        "TLSApplicationData",
    ] in scenario.interesting_paths

    assert len(scenario.happy_paths) == 3
    assert [
        ("TLS13ClientHello", set()),
        ("TLSFinished", {"TLSFinished"}),
        ("TLSApplicationData", set()),
    ] in scenario.happy_paths


def test_load_scenario_with_invalid_parameter_in_interesting_path():
    scenario_content = """[general]
name = wrong
role = client
tls_version = tls13
input_vocabulary = M1
interesting_paths = path

[path]
parameter = invalid_parameter
path = M1
"""
    input_file = io.StringIO(scenario_content)
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])


def test_load_scenario_with_unbalanced_happy_path():
    scenario_content = """[general]
name = wrong
role = client
tls_version = tls13
input_vocabulary = M1
happy_paths = path

[path]
path = M1
answers = A, B
"""
    input_file = io.StringIO(scenario_content)
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])


def test_load_scenario_with_empty_interesting_path():
    scenario_content = """[general]
name = wrong
role = client
tls_version = tls13
input_vocabulary = M1
happy_paths = path
"""
    input_file = io.StringIO(scenario_content)
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])

    scenario_content = """[general]
name = wrong
role = client
tls_version = tls13
input_vocabulary = M1
happy_paths = path

[path]
nothing = here
"""
    input_file = io.StringIO(scenario_content)
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])

    scenario_content = """[general]
name = wrong
role = client
tls_version = tls13
input_vocabulary = M1
happy_paths = path

[path]
path =
"""
    input_file = io.StringIO(scenario_content)
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])


def test_load_invalid_ini_file():
    input_file = io.StringIO("not_an_ini_file")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
    input_file = io.StringIO("[general]\nnot_an_ini_file")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
    input_file = io.StringIO("foo = bar")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])


def test_load_invalid_scenario_missing_params():
    input_file = io.StringIO("[general]\nfoo = bar")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
    input_file = io.StringIO("[general]\nname = bar")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
    input_file = io.StringIO("[general]\nname = bar\nrole=client")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
    input_file = io.StringIO("[general]\nname = bar\nrole=client\ntls_version=tls13")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])


def test_load_invalid_scenario_invalid_params():
    input_file = io.StringIO("[general]\nname = bar\nrole=proxy\ntls_version=tls13")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
    input_file = io.StringIO("[general]\nname = bar\nrole=client\ntls_version=tls7")
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])


def test_load_inconsistent_happy_path():
    scenario_content = """[general]
name = wrong
role = client
tls_version = tls13
input_vocabulary = A
happy_paths = path

[path]
path = B/
"""
    input_file = io.StringIO(scenario_content)
    with pytest.raises(ScenarioError):
        load_scenario(input_file, [])
