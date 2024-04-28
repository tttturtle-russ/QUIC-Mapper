def find_bb_oracle(automaton, good_msgs, bad_msgs):
    interesting_states = []

    for state in automaton.states:
        for good_msg in good_msgs:
            server_answer = automaton.follow_transition(state, good_msg)
            for bad_msg in bad_msgs:
                if automaton.follow_transition(state, bad_msg) != server_answer:
                    interesting_states.append(state)
                    break

    return interesting_states


# pylint: disable=too-many-arguments
def color_bb_oracle(
    automaton,
    good_msgs,
    bad_msgs,
    interesting_states,
    good_color="green",
    bad_color="red",
):
    if interesting_states:
        for state in interesting_states:
            deemed_good_behaviour = set()
            for sent_msg in good_msgs:
                next_state, recv_msgs, colors = automaton.states[state][sent_msg]
                colors.add(good_color)
                deemed_good_behaviour.add((next_state, "+".join(recv_msgs)))
            for sent_msg in bad_msgs:
                next_state, recv_msgs, colors = automaton.states[state][sent_msg]
                if (next_state, "+".join(recv_msgs)) in deemed_good_behaviour:
                    colors.add(good_color)
                else:
                    colors.add(bad_color)


def find_loops(automaton, messages_to_avoid, current_state=0, current_path=None):
    aggregated_result = []
    if not current_path:
        current_path = []

    for msg in automaton.input_vocabulary:
        if msg in messages_to_avoid:
            continue

        next_state, _, _ = automaton.states[current_state][msg]
        if automaton.is_sink_state(next_state):
            continue

        if next_state in [link[0] for link in current_path]:
            result = []
            for state, sent_msg in reversed(current_path + [(current_state, msg)]):
                result.append((state, sent_msg))
                if state == next_state:
                    result.reverse()
                    if result not in aggregated_result:
                        aggregated_result.append(result)
                    break
        else:
            recursive_result = find_loops(
                automaton,
                messages_to_avoid,
                current_state=next_state,
                current_path=current_path + [(current_state, msg)],
            )
            for loop in recursive_result:
                if loop not in aggregated_result:
                    aggregated_result.append(loop)

    return aggregated_result
