import pytest
from automata.automata import (
    extract_distinguishers,
    extract_pairwise_distinguishers,
    cover_distinguishers,
    get_outputs,
    fingerprint_automata,
    DifferentInputVocabulary,
    IndistinguishibleSetOfAutomata,
)


def test_distinguih_works_with_same_input_vocabulary(tls12_automaton, tls13_automaton):
    with pytest.raises(DifferentInputVocabulary):
        extract_distinguishers(tls12_automaton, tls13_automaton)


def test_distinguish_same(tls13_automaton):
    distinguishers = extract_distinguishers(tls13_automaton, tls13_automaton)
    assert not distinguishers


def test_distinguish(tls13_automaton, flawed_tls13_automaton):
    distinguishers = extract_distinguishers(tls13_automaton, flawed_tls13_automaton)
    assert distinguishers == [["SH", "EE", "Finished"]]


def test_get_fingerprint(tls13_automaton, flawed_tls13_automaton):
    distinguishers = ["SH", "EE", "Finished"]
    outputs = get_outputs([tls13_automaton, flawed_tls13_automaton], distinguishers)
    assert outputs[0] == [[], [], ["UnxpectedMsg"]]
    assert outputs[1] == [[], [], ["Finished", "AppData"]]


def test_pairwise_distinguishing(
    tls13_automaton, flawed_tls13_automaton, slightly_broken_tls13_automaton
):
    distinguishers = extract_pairwise_distinguishers(
        [tls13_automaton, flawed_tls13_automaton, slightly_broken_tls13_automaton]
    )
    assert len(distinguishers) == 3
    assert distinguishers[0] == [["SH", "EE", "Finished"]]
    assert distinguishers[1] == [["SH"]]
    assert distinguishers[2] == [["SH"]]


def test_cover_distinguishers():
    distinguishers = [[["A"], ["B"]], [["A"], ["C"]], [["A"], ["B"]], [["C"]]]
    covering_sequences = cover_distinguishers(distinguishers)
    assert covering_sequences == [["A"], ["C"]]


def test_fingerprint_automata(
    tls13_automaton, flawed_tls13_automaton, slightly_broken_tls13_automaton
):
    fingerprints = fingerprint_automata(
        [tls13_automaton, flawed_tls13_automaton, slightly_broken_tls13_automaton]
    )
    assert len(fingerprints) == 2
    assert (["SH"], [[[]], [[]], [["UselessWarning"]]]) in fingerprints
    assert (
        ["SH", "EE", "Finished"],
        [
            [[], [], ["UnxpectedMsg"]],
            [[], [], ["Finished", "AppData"]],
            [["UselessWarning"], [], ["UnxpectedMsg"]],
        ],
    ) in fingerprints


def test_fingerprint_automata_empty():
    with pytest.raises(IndistinguishibleSetOfAutomata):
        fingerprint_automata([])


def test_fingerprint_automata_same(tls13_automaton):
    with pytest.raises(IndistinguishibleSetOfAutomata):
        fingerprint_automata([tls13_automaton, tls13_automaton, tls13_automaton])
