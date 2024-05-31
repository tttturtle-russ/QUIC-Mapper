from typing import List, Tuple, Set
import pytest
from automata.automata import (
    Automaton,
    IncompleteInputVocabulary,
    MultipleDefinitionForATransition,
    convert_from_pylstar,
    load_automaton,
    load_automaton_from_file,
    use_star,
    use_star_and_prefer_green,
)


def test_load_automaton(tls12_automaton_content):
    automaton = load_automaton(tls12_automaton_content)
    assert len(automaton.states) == 6
    assert len(automaton.states[0]) == 6


def test_load_automaton_from_file(tls13_client_automaton_file):
    automaton = load_automaton_from_file(tls13_client_automaton_file)
    print(automaton.states.keys())
    assert len(automaton.states) == 7
    for transitions in automaton.states.values():
        assert len(transitions) == len(automaton.input_vocabulary)


def test_convert_from_pylstar(pylstar_automaton):
    pylstar_automata_object, input_vocabulary, local_object = pylstar_automaton
    automaton = convert_from_pylstar(input_vocabulary, pylstar_automata_object)
    assert automaton == local_object


def test_print_and_load(tls12_automaton):
    printed_version = f"{tls12_automaton}"
    reparsed_automaton = load_automaton(printed_version)
    assert tls12_automaton.states == reparsed_automaton.states


def test_multiple_transitions1(tls12_automaton):
    with pytest.raises(MultipleDefinitionForATransition):
        tls12_automaton.add_transition(1, 2, "CKE", [])


def test_run_automaton(tls12_automaton):
    assert tls12_automaton.run(["CH", "CKE", "CCS", "Fin", "AppData", "Close"]) == (
        5,
        [["SH", "Cert", "SHD"], [], [], ["CCS", "Fin"], ["AppData"], ["Close"]],
    )


def test_run_automaton_using_default_transition(tls12_automaton):
    assert tls12_automaton.run(["CH", "CCS"]) == (
        5,
        [["SH", "Cert", "SHD"], ["UnexpectedMsg"]],
    )


def test_compute_input_vocabulary(tls12_automaton):
    assert len(tls12_automaton.input_vocabulary) == 6
    assert "CH" in tls12_automaton.input_vocabulary
    assert "SH" not in tls12_automaton.input_vocabulary


def test_reorder_states(tls12_automaton):
    complete_automaton = tls12_automaton.reorder_states()
    assert len(complete_automaton.states) == 6
    for state in complete_automaton.states:
        assert len(complete_automaton.states[state]) == 6


def test_idempotence_reorder_states(tls12_automaton):
    complete_automaton = tls12_automaton.reorder_states()
    assert complete_automaton.states == complete_automaton.reorder_states().states


def test_remove_vocabulary1(tls12_automaton):
    restricted_automaton = tls12_automaton.remove_input_word("AppData")
    assert len(restricted_automaton.states) == 6
    assert len(restricted_automaton.input_vocabulary) == 5


def test_remove_vocabulary2(tls12_automaton):
    restricted_automaton = tls12_automaton.remove_input_word("Fin")
    assert len(restricted_automaton.states) == 5
    assert len(restricted_automaton.input_vocabulary) == 5


def test_sink_detection(tls12_automaton):
    assert tls12_automaton.is_sink_state(5)
    assert not tls12_automaton.is_sink_state(2)


def test_eq1(tls12_automaton_content):
    automaton = load_automaton(tls12_automaton_content)
    automaton2 = load_automaton(tls12_automaton_content)
    assert automaton == automaton2


def test_eq2(tls12_automaton):
    complete_automaton = tls12_automaton.reorder_states()
    assert tls12_automaton == complete_automaton


def test_contains_transition_with_received_msg(tls12_automaton):
    assert tls12_automaton.contains_transition_with_received_msg("AppData")
    assert tls12_automaton.contains_transition_with_received_msg("Fin")
    assert not tls12_automaton.contains_transition_with_received_msg("CH")


def test_color_automaton1(tls13_automaton, tls13_happy_path):
    found_path = tls13_automaton.extract_happy_path(tls13_happy_path)
    assert found_path

    tls13_automaton.color_path(found_path, "green")
    _, _, label1 = tls13_automaton.states[0]["SH"]
    _, _, label2 = tls13_automaton.states[1]["EE"]
    _, _, label3 = tls13_automaton.states[2]["Cert"]
    _, _, label4 = tls13_automaton.states[3]["CV"]
    _, _, label5 = tls13_automaton.states[4]["Finished"]
    assert label1 == {"green"}
    assert label2 == {"green"}
    assert label3 == {"green"}
    assert label4 == {"green"}
    assert label5 == {"green"}


def test_color_automaton2(tls13_automaton):
    path = [
        ("SH", set()),
        ("EE", set()),
        ("Cert", set()),
        ("CV", set()),
        ("Finished", {"Error"}),
    ]
    assert not tls13_automaton.extract_happy_path(path)


def test_dot1(tls12_automaton):
    dot_content = tls12_automaton.dot(use_star)
    assert (
        dot_content
        == """digraph {
"0" [shape=doubleoctagon];
"1" [shape=ellipse];
"2" [shape=ellipse];
"3" [shape=ellipse];
"4" [shape=ellipse];
"5" [shape=rectangle];
"0" -> "1" [label="CH / SH+Cert+SHD"];
"0" -> "5" [label="* / UnexpectedMsg"];
"1" -> "2" [label="CKE / "];
"1" -> "5" [label="* / UnexpectedMsg"];
"2" -> "3" [label="CCS / "];
"2" -> "5" [label="* / UnexpectedMsg"];
"3" -> "4" [label="Fin / CCS+Fin"];
"3" -> "5" [label="* / UnexpectedMsg"];
"4" -> "4" [label="AppData / AppData"];
"4" -> "5" [label="Close / Close"];
"4" -> "5" [label="* / UnexpectedMsg"];
"5" -> "5" [label="* / UnexpectedMsg"];
}
"""
    )


def test_dot2():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 1, "A", ["M"])
    automaton.add_transition(0, 1, "B", ["M"])
    automaton.add_transition(1, 1, "*", [])
    dot_content = automaton.dot()
    assert (
        dot_content
        == """digraph {
"0" [shape=doubleoctagon];
"1" [shape=rectangle];
"0" -> "1" [label="A-B / M"];
"1" -> "1" [label="A-B / "];
}
"""
    )


def test_dot3():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 1, "A", ["M"])
    automaton.add_transition(0, 1, "B", ["M"])
    automaton.add_transition(1, 1, "*", [])
    dot_content = automaton.dot(use_star)
    assert (
        dot_content
        == """digraph {
"0" [shape=doubleoctagon];
"1" [shape=rectangle];
"0" -> "1" [label="* / M"];
"1" -> "1" [label="* / "];
}
"""
    )


def test_dot4():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 1, "A", ["M"])
    automaton.add_transition(0, 1, "B", ["M"])
    automaton.add_transition(1, 2, "*", [])
    automaton.add_transition(2, 3, "A", ["M"])
    automaton.add_transition(2, 2, "B", [])
    automaton.add_transition(3, 3, "*", [])

    path_descripion: List[Tuple[str, Set[str]]] = [
        ("A", set()),
        ("A", set()),
        ("A", {"M"}),
    ]
    path = automaton.extract_happy_path(path_descripion)
    assert path
    automaton.color_path(path, "green")

    dot_content = automaton.dot(use_star)
    assert (
        dot_content
        == """digraph {
"0" [shape=doubleoctagon];
"1" [shape=ellipse];
"2" [shape=ellipse];
"3" [shape=rectangle];
"0" -> "1" [label="A / M", color="green", fontcolor="green"];
"0" -> "1" [label="B / M"];
"1" -> "2" [label="A / ", color="green", fontcolor="green"];
"1" -> "2" [label="B / "];
"2" -> "3" [label="A / M", color="green", fontcolor="green"];
"2" -> "2" [label="B / "];
"3" -> "3" [label="* / "];
}
"""
    )


def test_dot5():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 1, "A", ["M"], {"green", "red"})
    automaton.add_transition(0, 1, "B", ["M"])
    automaton.add_transition(1, 1, "*", [])
    dot_content = automaton.dot(use_star)
    assert (
        dot_content
        == """digraph {
"0" [shape=doubleoctagon];
"1" [shape=rectangle];
"0" -> "1" [label="A / M", color="green", fontcolor="green"];
"0" -> "1" [label="A / M", color="red", fontcolor="red"];
"0" -> "1" [label="B / M"];
"1" -> "1" [label="* / "];
}
"""
    )


def test_dot6():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 1, "A", ["M"], {"green", "red"})
    automaton.add_transition(0, 1, "B", ["M"])
    automaton.add_transition(1, 1, "*", [])

    dot_content = automaton.dot(use_star_and_prefer_green)

    assert (
        dot_content
        == """digraph {
"0" [shape=doubleoctagon];
"1" [shape=rectangle];
"0" -> "1" [label="A / M", color="green", fontcolor="green"];
"0" -> "1" [label="B / M"];
"1" -> "1" [label="* / "];
}
"""
    )


def test_rename_input_vocabulary(tls12_automaton):
    mapping = {"CH": "ClientHello"}
    new_automaton = tls12_automaton.rename_input_vocabulary(mapping)
    assert new_automaton.follow_transition(0, "ClientHello") == (
        1,
        ["SH", "Cert", "SHD"],
        set(),
    )
    assert "CH" not in new_automaton.input_vocabulary
    assert "ClientHello" in new_automaton.input_vocabulary
    assert "CKE" in new_automaton.input_vocabulary
    assert len(new_automaton.states) == 6


def test_rename_output_vocabulary(tls12_automaton):
    mapping = {"AppData": "ApplicationData"}
    new_automaton = tls12_automaton.rename_output_vocabulary(mapping)
    assert new_automaton.follow_transition(4, "AppData") == (
        4,
        ["ApplicationData"],
        set(),
    )
    assert len(new_automaton.states) == 6


def test_incomplete_input_vocabulary():
    content = """A B

0, 1, A,
0, 1, B,
0, 1, C,
1, 1, *"""
    with pytest.raises(IncompleteInputVocabulary):
        load_automaton(content)


def test_minimization1():
    content = """A B C
0, 1, A, X
0, 2, B, Y
1, 3, C,
2, 3, C,
3, 3, *,
0, 4, *,
1, 4, *,
2, 4, *,
4, 4, *,"""
    automaton = load_automaton(content)
    assert len(automaton.states) == 5

    new_automaton = automaton.minimize()
    assert len(new_automaton.states) == 4


def test_minimization2():
    content = """A B C
0, 1, A,
0, 2, B,
1, 3, C, X
2, 3, C, Y
3, 3, *,
0, 4, *,
1, 4, *,
2, 4, *,
4, 4, *,"""
    automaton = load_automaton(content)
    assert len(automaton.states) == 5

    mapping = {"Y": "X"}
    new_automaton = automaton.rename_output_vocabulary(mapping)
    assert len(new_automaton.states) == 5

    new_automaton.minimize()
    assert len(new_automaton.states) == 4
