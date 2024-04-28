from automata.automata import Automaton, message_was_not_sent
from automata.vulnerabilities import find_bb_oracle, color_bb_oracle, find_loops


def test_find_bb_oracle1(tls12_automaton):
    tls12_automaton.input_vocabulary.add("CKE_bad")
    tls12_automaton.add_transition(1, 2, "CKE_bad", [])
    for state in tls12_automaton.states:
        if state == 1:
            continue
        tls12_automaton.add_transition(state, 5, "CKE_bad", ["UnexpectedMsg"])
    assert not find_bb_oracle(tls12_automaton, good_msgs=["CKE"], bad_msgs=["CKE_bad"])


def test_find_bb_oracle2(tls12_automaton):
    tls12_automaton.input_vocabulary.add("CKE_bad")
    tls12_automaton.add_transition(1, 2, "CKE_bad", ["Warning"])
    for state in tls12_automaton.states:
        if state == 1:
            continue
        tls12_automaton.add_transition(state, 5, "CKE_bad", ["UnexpectedMsg"])
    good_msgs = ["CKE"]
    bad_msgs = ["CKE_bad"]
    interesting_states = find_bb_oracle(tls12_automaton, good_msgs, bad_msgs)
    assert interesting_states == [1]

    color_bb_oracle(tls12_automaton, good_msgs, bad_msgs, interesting_states)
    assert tls12_automaton.states[1]["CKE_bad"][2] == {"red"}
    assert tls12_automaton.states[1]["CKE"][2] == {"green"}


def test_find_bb_oracle3(tls12_automaton):
    tls12_automaton.input_vocabulary.add("CKE_bad")
    tls12_automaton.add_transition(1, 6, "CKE_bad", [])
    tls12_automaton.add_transition(6, 5, "*", [])
    for state in tls12_automaton.states:
        if state in [1, 6]:
            continue
        tls12_automaton.add_transition(state, 5, "CKE_bad", ["UnexpectedMsg"])

    good_msgs = ["CKE"]
    bad_msgs = ["CKE_bad"]
    interesting_states = find_bb_oracle(tls12_automaton, good_msgs, bad_msgs)
    assert interesting_states == [1]

    color_bb_oracle(tls12_automaton, good_msgs, bad_msgs, interesting_states)
    assert tls12_automaton.states[1]["CKE_bad"][2] == {"red"}
    assert tls12_automaton.states[1]["CKE"][2] == {"green"}


def test_find_bb_oracle4(tls12_automaton):
    tls12_automaton.input_vocabulary.add("CKE_bad")
    tls12_automaton.input_vocabulary.add("CKE_worse")
    tls12_automaton.add_transition(1, 2, "CKE_bad", ["Warning"])
    tls12_automaton.add_transition(1, 2, "CKE_worse", [])
    for state in tls12_automaton.states:
        if state == 1:
            continue
        tls12_automaton.add_transition(state, 5, "CKE_worse", ["UnexpectedMsg"])
        tls12_automaton.add_transition(state, 5, "CKE_bad", ["UnexpectedMsg"])

    good_msgs = ["CKE"]
    bad_msgs = ["CKE_bad", "CKE_worse"]
    interesting_states = find_bb_oracle(tls12_automaton, good_msgs, bad_msgs)
    assert interesting_states == [1]

    color_bb_oracle(
        tls12_automaton, good_msgs, bad_msgs, interesting_states, "yellow", "blue"
    )
    assert tls12_automaton.states[1]["CKE_bad"][2] == {"blue"}
    assert tls12_automaton.states[1]["CKE"][2] == {"yellow"}
    assert tls12_automaton.states[1]["CKE_worse"][2] == {"yellow"}


def test_find_loops1():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 0, "A", [])
    automaton.add_transition(0, 1, "B", [])
    automaton.add_transition(1, 1, "*", [])

    loops = find_loops(automaton, ["B"])
    assert loops == [[(0, "A")]]


def test_find_loops2():
    automaton = Automaton({"A", "B"})
    automaton.add_transition(0, 1, "A", [])
    automaton.add_transition(1, 0, "A", [])
    automaton.add_transition(0, 2, "B", [])
    automaton.add_transition(1, 2, "B", [])
    automaton.add_transition(2, 2, "*", [])

    loops = find_loops(automaton, ["B"])
    assert loops == [[(0, "A"), (1, "A")]]


def test_find_loops3():
    automaton = Automaton({"A", "B", "C"})
    automaton.add_transition(0, 1, "*", [])
    automaton.add_transition(1, 1, "A", [])
    automaton.add_transition(1, 2, "B", [])
    automaton.add_transition(1, 2, "C", [])
    automaton.add_transition(2, 2, "*", [])

    loops = find_loops(automaton, ["B"])
    assert loops == [[(1, "A")]]


def test_find_loops4():
    automaton = Automaton({"A", "B", "C"})
    automaton.add_transition(0, 0, "A", [])
    automaton.add_transition(0, 1, "B", [])
    automaton.add_transition(0, 0, "C", [])
    automaton.add_transition(1, 1, "*", [])

    loops = find_loops(automaton, ["B", "C"])
    assert loops == [[(0, "A")]]


def test_detect_flawed_transition(flawed_tls13_automaton):
    all_paths = flawed_tls13_automaton.enumerate_paths_until_recv_msg("AppData")
    vulnerable_paths = filter(lambda path: message_was_not_sent(path, "CV"), all_paths)
    assert len(list(vulnerable_paths)) > 0
