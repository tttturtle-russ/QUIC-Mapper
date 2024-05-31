from pylstar.tools.Decorators import PylstarLogger
from pylstar.Word import Word
from pylstar.OutputQuery import OutputQuery


@PylstarLogger
class HappyPathFirst:
    def __init__(self, knowledge_base, happy_paths, next_eq_method):
        self.knowledge_base = knowledge_base
        self.happy_paths = happy_paths
        self.next_eq_method = next_eq_method

    def find_counterexample(self, hypothesis):
        if hypothesis is None:
            raise Exception("Hypothesis cannot be None")

        self._logger.info(
            "Starting the HappyPath Algorithm to search for a counter-example"
        )

        while self.happy_paths:
            path = self.happy_paths.pop()
            query = OutputQuery(Word(letters=path))
            try:
                (hypothesis_output_word, _) = hypothesis.play_query(query)
                counterexample_query = self.__check_equivalence(
                    query, hypothesis_output_word
                )
                if counterexample_query is not None:
                    return counterexample_query
            except Exception as e:
                self._logger.warn(e)

        return self.next_eq_method.find_counterexample(hypothesis)

    def __check_equivalence(self, query, expected_output_word):
        self.knowledge_base.resolve_query(query)

        if query.output_word != expected_output_word:
            self._logger.info(
                "Found a counter-example : input: '{}', expected: '{}', observed: '{}'".format(
                    query.input_word, expected_output_word, query.output_word
                )
            )
            return query
        return None
