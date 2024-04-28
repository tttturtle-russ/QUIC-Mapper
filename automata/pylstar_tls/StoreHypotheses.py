import time
from pylstar.tools.Decorators import PylstarLogger
from pylstar.Word import Word
from pylstar.OutputQuery import OutputQuery
from automata.automata import convert_from_pylstar


@PylstarLogger
class StoreHypotheses:
    def __init__(self, knowledge_base, input_vocab, output_dir, eq_method):
        self.knowledge_base = knowledge_base
        self.eq_method = eq_method
        self.input_vocabulary = input_vocab
        self.output_dir = output_dir
        self.current_hypothesis = 0
        self.start = time.time()

    def mk_current_filename(self, extension):
        filename = f"{self.output_dir}/{self.current_hypothesis}.{extension}"
        return filename

    def write_stats(self, hypothesis, stats_filename=None, first_line=None):
        if not stats_filename:
            stats_filename = self.mk_current_filename("stats")
        if first_line:
            self._logger.info(first_line)

        duration = time.time() - self.start

        self._logger.info(f"  time spent so far: {duration}")
        self._logger.info(f"  n_states: {len(hypothesis.get_states())}")
        self._logger.info(f"  n_queries={self.knowledge_base.stats.nb_query}")
        self._logger.info(
            f"  n_submitted_queries={self.knowledge_base.stats.nb_submited_query}"
        )
        self._logger.info(f"  n_letters={self.knowledge_base.stats.nb_letter}")
        self._logger.info(
            f"  n_submitted_letters={self.knowledge_base.stats.nb_submited_letter}"
        )

        with open(stats_filename, "w", encoding="utf-8") as fd:
            if first_line:
                fd.write(f"{first_line}\n")
            fd.write(f"  time spent so far: {duration}\n")
            fd.write(f"  n_states: {len(hypothesis.get_states())}\n")
            fd.write(f"  n_queries={self.knowledge_base.stats.nb_query}\n")
            fd.write(
                f"  n_submitted_queries={self.knowledge_base.stats.nb_submited_query}\n"
            )
            fd.write(f"  n_letters={self.knowledge_base.stats.nb_letter}\n")
            fd.write(
                f"  n_submitted_letters={self.knowledge_base.stats.nb_submited_letter}\n"
            )

    def find_counterexample(self, hypothesis):
        if hypothesis is None:
            raise Exception("Hypothesis cannot be None")

        filename = self.mk_current_filename("automaton")

        self._logger.info(
            f"Storing hyptohesis #{self.current_hypothesis} in {filename}"
        )
        self.write_stats(hypothesis)
        automaton = convert_from_pylstar(self.input_vocabulary, hypothesis)
        with open(filename, "w", encoding="utf-8") as fd:
            fd.write(f"{automaton}\n")

        counterexample = self.eq_method.find_counterexample(hypothesis)
        if counterexample:
            stats_filename = (
                f"{self.output_dir}/{self.current_hypothesis}.counterexample"
            )
            first_line = f"Found a counterexample: {counterexample}"
            self.write_stats(hypothesis, stats_filename, first_line)
        else:
            stats_filename = f"{self.output_dir}/final.stats"
            first_line = "Inference converged"
            self.write_stats(hypothesis, stats_filename, first_line)

        self.current_hypothesis += 1
        return counterexample
