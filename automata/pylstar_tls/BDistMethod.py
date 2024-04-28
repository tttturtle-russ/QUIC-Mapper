from typing import List, Tuple
from pylstar.automata.Automata import Automata
from pylstar.Word import Word
from pylstar.OutputQuery import OutputQuery
from pylstar.tools.Decorators import PylstarLogger
from pylstar.Letter import Letter
from itertools import product

"""
Implementation of the BDist equivalency method based on the "DroidStar : Callback Typestates for Android Classes" paper

eqtests = BDistMethod(self.knowledge_base, self.input_letters, distinguishing_bound)
"""


@PylstarLogger
class BDistMethod:
    def __init__(self, knowledge_base, input_letters: List[Letter], bdist: int):
        self.knowledge_base = knowledge_base
        self.input_letters = input_letters
        self.bdist = bdist
        self.suffix_list: List[Word] = []
        for i in range(1, self.bdist + 1):
            for suffix_tuple in product(self.input_letters, repeat=i):
                self.suffix_list.append(Word(list(suffix_tuple)))

    def find_counterexample(self, hypothesis: Automata):
        self._logger.info(
            "Starting the BDistMethod Algorithm to search for a counter-example"
        )

        representatives: dict[str, Word] = self.get_representatives(hypothesis)

        for q in hypothesis.get_states():
            for letter in self.input_letters:
                word = Word([letter])
                w_i = representatives[q.name] + word
                out = hypothesis.play_word(word, q)

                query = OutputQuery(w_i)
                self.knowledge_base.resolve_query(query)

                if out[0].last_letter() != query.output_word.last_letter():
                    return query

                q_prime = out[1][-1]  # The last state visited by playing the word
                w_i_prime = representatives[q_prime.name]
                if w_i == w_i_prime:
                    continue

                suffix, query_i, query_i_prime = self.__check_equivalence(
                    w_i, w_i_prime
                )
                if suffix:
                    expected_output_word = hypothesis.play_word(w_i + suffix)[0].letters
                    if expected_output_word != query_i.output_word.letters:
                        query = query_i
                    else:
                        expected_output_word = hypothesis.play_word(w_i_prime + suffix)[
                            0
                        ].letters
                        query = query_i_prime
                    self._logger.info(
                        "Found a counter-example : input: '{}', expected: '{}', observed: '{}'".format(
                            query.input_word, expected_output_word, query.output_word
                        )
                    )
                    return query
        return None

    def get_representatives(self, automaton: Automata):
        """get_representatives searches the automaton using a BFS strategy.

        It returns a dictionary that, for each state, to gives a word
        of the shortest length possible to reach this state."""
        nb_states = len(automaton.get_states())
        currentState = automaton.initial_state
        representatives = {currentState.name: Word([])}
        to_analyze = [
            (
                t.output_state,
                representatives[currentState.name] + Word([t.input_letter]),
            )
            for t in currentState.transitions
            if t.output_state.name != currentState.name
        ]
        while len(to_analyze) > 0 and len(representatives) < nb_states:
            (currentState, in_word) = to_analyze.pop()
            if currentState.name not in representatives.keys():
                representatives[currentState.name] = in_word
                to_analyze = to_analyze + [
                    (
                        t.output_state,
                        representatives[currentState.name] + Word([t.input_letter]),
                    )
                    for t in currentState.transitions
                    if t.output_state.name not in representatives.keys()
                ]
        return representatives

    def __check_equivalence(self, w_i: Word, w_i_prime: Word):
        for suffix in self.suffix_list:
            query_i = OutputQuery(w_i + suffix)
            query_i_prime = OutputQuery(w_i_prime + suffix)
            self.knowledge_base.resolve_query(query_i)
            self.knowledge_base.resolve_query(query_i_prime)
            if (
                query_i.output_word.last_letter()
                != query_i_prime.output_word.last_letter()
            ):
                return suffix, query_i, query_i_prime
        return None, None, None
