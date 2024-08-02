import logging
from typing import List, Dict, Tuple, Set, Iterator, Optional
from itertools import combinations, product
import hashlib
import pylstar.automata.Automata
from pylstar.Letter import Letter


class IncompleteInputVocabulary(BaseException):
    pass


class MultipleDefinitionForATransition(BaseException):
    pass


class DifferentInputVocabulary(BaseException):
    pass


class IndistinguishibleSetOfAutomata(BaseException):
    pass


Path = List[Tuple[int, str]]
TransitionList = Dict[str, Tuple[int, List[str], Set[str]]]


def message_was_not_sent(path: Path, msg: str) -> bool:
    relevant_transitions = [sent_msg for _, sent_msg in path if sent_msg == msg]
    return len(relevant_transitions) == 0


def use_star(colors):
    return colors, len(colors) == 0


def use_star_and_prefer_green(colors):
    if "green" in colors:
        return ["green"], False
    return colors, len(colors) == 0


class Automaton:
    def __init__(self, input_vocabulary: Set[str]):
        self.states: Dict[int, TransitionList] = {}
        self.input_vocabulary = input_vocabulary
        self.hash: Optional[bytes] = None

    def __str__(self):
        # vocabulary = list(self.input_vocabulary)
        vocabulary = []
        for letter in self.input_vocabulary:
            for symbol in letter.symbols:
                vocabulary.append(symbol)
        vocabulary.sort()
        result = [" ".join(vocabulary)]
        for state in sorted(self.states):
            # print(type(self.states[state]))
            for input_word in (self.states[state]):
                output_state, output_words, _ = self.states[state][input_word]
                output_words_s = "+".join(output_words)
                result.append(
                    f"{state}, {output_state}, {input_word}, {output_words_s}"
                )
        return "\n".join(result)

    def compute_hash(self) -> bytes:
        if not self.hash:
            complete_automaton = self.reorder_states()
            automaton_repr = str(complete_automaton).encode("utf-8")
            self.hash = hashlib.md5(automaton_repr).digest()
        return self.hash

    def __eq__(self, other):
        return self.compute_hash() == other.compute_hash()

    def add_state(self, state: int):
        self.hash = None
        if state not in self.states:
            self.states[state] = {}

    # pylint: disable=too-many-arguments
    def add_transition(
        self,
        input_state: int,
        output_state: int,
        input_word: str,
        output_words: List[str],
        colors: Set[str] = None,
    ):
        # if (input_word not in self.input_vocabulary and Letter(input_word) not in self.input_vocabulary) and input_word != "*":
        #     raise IncompleteInputVocabulary(input_word, self.input_vocabulary)
        self.hash = None
        self.add_state(input_state)
        self.add_state(output_state)
        if not colors:
            colors = set()
        if input_word != "*":
            if input_word in self.states[input_state]:
                return
                # raise MultipleDefinitionForATransition(input_state, input_word)
            transition_content = (output_state, output_words, colors)
            self.states[input_state][input_word] = (output_state, output_words, colors)
        else:
            for word in self.input_vocabulary:
                if word not in self.states[input_state]:
                    transition_content = (output_state, output_words, colors.copy())
                    self.states[input_state][word] = transition_content

    def follow_transition(self, state: int, msg: str):
        _msg = None
        if isinstance(msg, Letter):
            for symbol in msg.symbols:
                _msg = symbol
        print(_msg)
        logging.warn(_msg)
        return self.states[state][_msg]

    def run(
        self, msg_sequence: List[str], initial_state=0
    ) -> Tuple[int, List[List[str]]]:
        current_state = initial_state
        output = []
        for msg in msg_sequence:
            current_state, output_words, _ = self.follow_transition(current_state, msg)
            output.append(output_words)
        return current_state, output

    def reorder_states(self):
        state_mapping = self.browse_automaton_and_build_mapping()
        return self.produce_automaton_from_state_mapping(state_mapping)

    def browse_automaton_and_build_mapping(self) -> Dict[int, int]:
        src_states_to_visit = [0]
        src_sink_states_to_visit: List[int] = []
        state_mapping = {}
        dst_current_state = 0
        listed_states = set([0])

        # First, we explore the non-sink states
        while src_states_to_visit:
            src_current_state = src_states_to_visit.pop(0)
            state_mapping[src_current_state] = dst_current_state
            dst_current_state += 1

            for msg in sorted(self.states[src_current_state]):
                output_state, _, _ = self.states[src_current_state][msg]
                if output_state in listed_states:
                    continue
                listed_states.add(output_state)
                if self.is_sink_state(output_state):
                    src_sink_states_to_visit.append(output_state)
                else:
                    src_states_to_visit.append(output_state)

        # Then, we explore sink states, which is a lot simpler
        while src_sink_states_to_visit:
            src_current_state = src_sink_states_to_visit.pop(0)
            state_mapping[src_current_state] = dst_current_state
            dst_current_state += 1

        return state_mapping

    def produce_automaton_from_state_mapping(self, state_mapping):
        result = Automaton(self.input_vocabulary)
        for input_state in state_mapping:
            for input_word in self.input_vocabulary:
                output_state, output_words, colors = self.follow_transition(
                    input_state, input_word
                )
                result.add_transition(
                    state_mapping[input_state],
                    state_mapping[output_state],
                    input_word,
                    output_words,
                    colors,
                )
        return result

    def remove_input_word(self, word_to_remove):
        new_vocabulary = self.input_vocabulary
        new_vocabulary.remove(word_to_remove)
        result = Automaton(new_vocabulary)
        for input_state, transitions in self.states.items():
            for input_word in transitions:
                if input_word == word_to_remove:
                    continue
                output_state, output_words, colors = transitions[input_word]
                result.add_transition(
                    input_state, output_state, input_word, output_words, colors
                )
        return result.reorder_states()

    def is_sink_state(self, state):
        for output_state, _, _ in self.states[state].values():
            if output_state != state:
                return False
        return True

    def contains_transition_with_received_msg(self, msg):
        for state in self.states.values():
            for _, output_words, _ in state.values():
                if msg in output_words:
                    return True
        return False

    def enumerate_paths_until_recv_msg(
        self, expected_message: str
    ) -> Iterator[List[Tuple[int, str]]]:
        yield from self._enumerate_paths_until_recv_msg(0, [], expected_message)

    def _enumerate_paths_until_recv_msg(
        self, state: int, path: Path, expected_message: str
    ) -> Iterator[Path]:
        for sent_msg in self.states[state]:
            next_state, recv_msgs, _ = self.states[state][sent_msg]
            new_path = path + [(state, sent_msg)]
            previous_states = [link[0] for link in new_path]
            if next_state not in previous_states:
                if expected_message in recv_msgs:
                    yield new_path
                else:
                    yield from self._enumerate_paths_until_recv_msg(
                        next_state, new_path, expected_message
                    )

    def extract_happy_path(
        self, path: List[Tuple[str, Set[str]]]
    ) -> Optional[List[Tuple[int, str]]]:
        path_to_color: List[Tuple[int, str]] = []
        state = 0
        for sent_msg, expected_msgs in path:
            next_state, received_msgs, _ = self.follow_transition(state, sent_msg)
            path_to_color.append((state, sent_msg))
            if expected_msgs:
                if not set(received_msgs).intersection(expected_msgs):
                    # None of the expected messages has been received
                    return None

            state = next_state

        return path_to_color

    def color_path(self, path: List[Tuple[int, str]], color: str):
        for state, sent_msg in path:
            _, _, colors = self.follow_transition(state, sent_msg)
            colors.add(color)

    def dot(self, dot_policy=None):
        states = []
        transitions = []
        for state in sorted(self.states):
            states.append(self._dot_state(state))
            transitions_to_merge: Dict[str, List[str]] = {}
            starrable_transitions: Set[str] = set()
            for sent_msg in sorted(self.states[state]):
                self._register_transition(
                    transitions_to_merge,
                    starrable_transitions,
                    state,
                    sent_msg,
                    dot_policy,
                )
            transitions.extend(
                self._commit_transitions(transitions_to_merge, starrable_transitions)
            )
        return "digraph {\n" + "\n".join(states + transitions) + "\n}\n"

    def _dot_state(self, state):
        if state == 0:
            shape = "doubleoctagon"
        elif self.is_sink_state(state):
            shape = "rectangle"
        else:
            shape = "ellipse"
        return f'"{state}" [shape={shape}];'

    def _register_transition(
        self,
        transitions_to_merge: Dict[str, List[str]],
        starrable_transitions,
        state,
        sent_msg,
        dot_policy,
    ):
        next_state, recv_msgs, colors = self.states[state][sent_msg]
        recv_msgs_str = "+".join(recv_msgs)
        params = f'label="%s / {recv_msgs_str}"'
        if dot_policy:
            colors, starrable = dot_policy(colors)
        else:
            starrable = False

        lines_to_fill = []
        if colors:
            for color in sorted(colors):
                lines_to_fill.append(
                    f'"{state}" -> "{next_state}" [{params}, color="{color}", fontcolor="{color}"];'
                )
        else:
            lines_to_fill = [f'"{state}" -> "{next_state}" [{params}];']

        for line_to_fill in lines_to_fill:
            if starrable:
                starrable_transitions.add(line_to_fill)
            if line_to_fill not in transitions_to_merge:
                transitions_to_merge[line_to_fill] = []
            transitions_to_merge[line_to_fill].append(sent_msg)

    def _commit_transitions(self, transitions_to_merge, starrable_transitions):
        star_line = None
        max_factor = 0
        for line_to_fill in transitions_to_merge:
            factor = len(transitions_to_merge[line_to_fill])
            if line_to_fill in starrable_transitions and factor > max_factor:
                max_factor = factor
                star_line = line_to_fill
        if max_factor <= 1:
            star_line = None

        for line_to_fill in transitions_to_merge:
            if line_to_fill == star_line:
                continue
            sent_msgs = transitions_to_merge[line_to_fill]
            sent_msgs_str = "-".join(sent_msgs)
            yield line_to_fill % sent_msgs_str

        if star_line:
            # pylint: disable=consider-using-f-string
            yield star_line % "*"

    def rename_input_vocabulary(self, mapping: Dict[str, str]):
        new_vocabulary = set()
        for word in self.input_vocabulary:
            if word in mapping:
                new_vocabulary.add(mapping[word])
            else:
                new_vocabulary.add(word)
        result = Automaton(new_vocabulary)

        for state, transitions in self.states.items():
            for word in transitions:
                if word in mapping:
                    sent_msg = mapping[word]
                else:
                    sent_msg = word
                output = transitions[word]
                result.add_transition(state, output[0], sent_msg, output[1], output[2])
        return result

    def rename_output_vocabulary(self, mapping: Dict[str, str]):
        result = Automaton(self.input_vocabulary)
        result.input_vocabulary = self.input_vocabulary
        for state, transitions in self.states.items():
            for sent_msg, output in transitions.items():
                new_recv_msgs = []
                for word in output[1]:
                    if word in mapping:
                        new_recv_msgs.append(mapping[word])
                    else:
                        new_recv_msgs.append(word)
                result.add_transition(
                    state, output[0], sent_msg, new_recv_msgs, output[2]
                )
        return result

    def minimize(self):
        states_to_merge = self._find_states_to_merge()
        while states_to_merge:
            for state_list in states_to_merge:
                self._merge_state(state_list)
            states_to_merge = self._find_states_to_merge()
        return self

    def _find_states_to_merge(self):
        behaviours: Dict[str, List[int]] = {}
        for state, transitions in self.states.items():
            behaviour = str(sorted(transitions.items()))
            if behaviour not in behaviours:
                behaviours[behaviour] = []
            behaviours[behaviour].append(state)

        result = []
        for behaviour_description in behaviours.values():
            if len(behaviour_description) > 1:
                result.append(behaviour_description)
        return result

    def _merge_state(self, state_list):
        merged_state = state_list.pop(0)
        for transitions in self.states.values():
            for sent_msg, output in transitions.items():
                next_state, recv_msgs, colors = output
                if next_state in state_list:
                    transitions[sent_msg] = merged_state, recv_msgs, colors
        for state in state_list:
            self.states.pop(state)

    def compute_bdist(self):
        """
        Return b_dist (int), the distinguishing bound for the state machine,
        and a dictionnary of state pairs/sequences leading to the bound.
        """
        nb_states = len(self.states)

        b_dist = 0
        b_pairs: Dict[str, List[str]] = {}

        for pair in combinations(range(nb_states), 2):
            break_var = False
            for loop_index in range(1, nb_states):
                if break_var:
                    break
                for word in product(sorted(self.input_vocabulary), repeat=loop_index):
                    output_words1 = self.run(list(word), initial_state=pair[0])[1]
                    output_words2 = self.run(list(word), initial_state=pair[1])[1]
                    if output_words1 != output_words2:
                        if b_dist <= loop_index:
                            b_dist = loop_index
                            b_pairs[f"({pair[0]}, {pair[1]})"] = list(word)
                        break_var = True
                        break

            if break_var:
                continue

        b_pairs = {k: v for (k, v) in b_pairs.items() if len(v) == b_dist}
        return b_dist, b_pairs


def convert_from_pylstar(
    input_vocabulary: List[str], pylstar_automaton: pylstar.automata.Automata.Automata
) -> Automaton:
    automaton = Automaton(set(input_vocabulary))

    for input_state in pylstar_automaton.get_states():
        for transition in input_state.transitions:
            input_word, output_words = transition.label.split("/")
            input_word = input_word.strip().strip("'")
            # if not isinstance(input_word, Letter):
            #     input_word = Letter(input_word)
            # print(input_word)
            output_words = [m.strip() for m in output_words.split("+") if m.strip()]
            automaton.add_transition(
                int(input_state.name),
                int(transition.output_state.name),
                input_word,
                output_words,
            )

    return automaton.reorder_states()

def convert_from_pylstar_to_dot(
    input_vocabulary: List[str],
    pylstar_automaton: pylstar.automata.Automata.Automata
) -> str:
    # 开始构造DOT字符串
    dot_content = 'digraph "Automata" {\n'

    # 定义默认的状态和转换属性
    dot_content += '  node [style=filled, fillcolor=white];\n'

    # 遍历pylstar自动机中的所有状态，并决定每个状态的形状
    state_shapes = {}
    for state in pylstar_automaton.get_states():
        # 假设状态名为"0"是初始状态，其余为常规状态
        shape = "doubleoctagon" if state.name == "0" else "ellipse"
        state_shapes[state.name] = shape
        dot_content += f'  "{state.name}" [shape={shape}, URL="{state.name}"];\n'

    # 遍历所有状态的所有转换
    for input_state in pylstar_automaton.get_states():
        for transition in input_state.transitions:
            input_word, output_words = transition.label.split("/")
            input_word = input_word.strip().strip("'")
            output_words = [m.strip() for m in output_words.split("+") if m.strip()]
            output_words_str = ":".join(output_words)  # 使用冒号分隔输出字
            label = f"{input_word} / {output_words_str}"
            dot_content += f'  "{input_state.name}" -> "{transition.output_state.name}" [fontsize=5, label="{label}", URL="{transition.name}"];\n'

    dot_content += '}\n'  # 结束图的定义
    return dot_content




def load_automaton(content: str) -> Automaton:
    lines = content.split("\n")
    input_vocabulary = [word.strip() for word in lines[0].split(" ")]
    automaton = Automaton(set(input_vocabulary))
    for line in lines[1:]:
        if not line.strip():
            continue
        input_state_s, output_state_s, input_word, output_words_s = line.split(",")
        input_state = int(input_state_s)
        output_state = int(output_state_s)
        input_word = input_word.strip()
        output_words = [m.strip() for m in output_words_s.split("+") if m.strip()]
        automaton.add_transition(input_state, output_state, input_word, output_words)
    return automaton


def load_automaton_from_file(filename: str) -> Automaton:
    with open(filename, encoding="utf-8") as automaton_file:
        content = automaton_file.read()
    return load_automaton(content)


def extract_distinguishers(
    automaton1: Automaton, automaton2: Automaton
) -> List[List[str]]:
    if automaton1.input_vocabulary != automaton2.input_vocabulary:
        raise DifferentInputVocabulary

    vocabulary = automaton1.input_vocabulary
    max_depth = max(len(automaton1.states), len(automaton2.states))
    distinguishing_sequences = []

    def find_differences(current_sequence: List[str], state1: int, state2: int):
        if len(current_sequence) == max_depth - 1:
            return

        for word in vocabulary:
            explored_sequence = current_sequence + [word]
            next_state1, recv_msgs1, _ = automaton1.states[state1][word]
            next_state2, recv_msgs2, _ = automaton2.states[state2][word]
            if recv_msgs1 == recv_msgs2:
                if next_state1 != state1 or next_state2 != state2:
                    find_differences(explored_sequence, next_state1, next_state2)
            else:
                distinguishing_sequences.append(explored_sequence)

    find_differences([], 0, 0)
    return distinguishing_sequences


def extract_pairwise_distinguishers(automata: List[Automaton]) -> List[List[List[str]]]:
    distinguishers = []
    for index, automaton1 in enumerate(automata):
        for automaton2 in automata[index + 1 :]:
            distinguisher = extract_distinguishers(automaton1, automaton2)
            if distinguisher:
                distinguishers.append(distinguisher)
    return distinguishers


def cover_distinguishers(distinguishers: List[List[List[str]]]) -> List[List[str]]:
    def find_next_best_sequence(distinguishers: List[List[List[str]]]) -> List[str]:
        sequence_counts: Dict[str, int] = {}
        max_count = 0
        best_sequence = []
        for distinguisher in distinguishers:
            for sequence in distinguisher:
                sequence_str = ", ".join(sequence)
                new_count = sequence_counts.get(sequence_str, 0) + 1
                sequence_counts[sequence_str] = new_count
                if new_count >= max_count:
                    best_sequence = sequence
                    max_count = new_count
        return best_sequence

    def remove_covered_distinguishers(
        distinguishers: List[List[List[str]]], sequence: List[str]
    ):
        return [
            distinguisher
            for distinguisher in distinguishers
            if sequence not in distinguisher
        ]

    remaining_distinguishers = distinguishers
    distinguishing_sequences = []
    while remaining_distinguishers:
        next_sequence = find_next_best_sequence(remaining_distinguishers)
        remaining_distinguishers = remove_covered_distinguishers(
            remaining_distinguishers, next_sequence
        )
        distinguishing_sequences.append(next_sequence)
    return distinguishing_sequences


def get_outputs(
    automata: List[Automaton], sequence: List[str]
) -> List[List[List[str]]]:
    return [automaton.run(sequence)[1] for automaton in automata]


def fingerprint_automata(
    automata: List[Automaton],
) -> List[Tuple[List[str], List[List[List[str]]]]]:
    distinguishers = extract_pairwise_distinguishers(automata)
    if not distinguishers:
        raise IndistinguishibleSetOfAutomata

    covering_sequences = cover_distinguishers(distinguishers)
    return [
        (sequence, get_outputs(automata, sequence)) for sequence in covering_sequences
    ]
