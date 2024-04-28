#!/usr/bin/env python

import os
import os.path
import sys
import time
import logging

from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter
from pylstar.Word import Word

import config.scenarios
import tls_args
from utils import (
    fill_answer_with,
    get_expected_output,
    read_next_msg,
)
from HappyPathFirst import HappyPathFirst
from StoreHypotheses import StoreHypotheses
from stubs.client_concretization import InfererTools
from automata.automata import convert_from_pylstar


class TLSServerKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, tls_version, options):
        super().__init__()
        self.tools = InfererTools(
            options.remote_endpoint,
            options.crypto_material,
            tls_version,
        )
        self.tls_session = None
        self.options = options

    def start(self):
        pass

    def stop(self):
        pass

    def start_target(self):
        pass

    def stop_target(self):
        if self.tls_session:
            self.tls_session.stop()

    def submit_word(self, word):
        n = len(word.letters)

        expected_letters = get_expected_output(word, self.knowledge_tree)
        if len(expected_letters) == n:
            return Word(letters=expected_letters)

        self.tls_session = self.tools.get_tls_session()

        output_letters = []
        for i in range(n):
            if self.options.verbose:
                msg_to_send = "+".join(list(word.letters[i].symbols))
                self.options.log(msg_to_send)

            expected_letter = None
            if expected_letters:
                expected_letter = expected_letters.pop(0)

            output_letter = self.send_and_receive(
                expected_letter, word.letters[i].symbols
            )

            if self.options.verbose:
                self.options.log(f" => {output_letter}\n")

            output_letters.append(Letter(output_letter))
            if output_letter == "EOF":
                output_letters = fill_answer_with(output_letters, "EOF", n)
                break

        if self.options.verbose:
            self.options.log("\n")
        return Word(letters=output_letters)

    def send_and_receive(self, expected_output, symbols):
        try:
            self.tools.concretize_client_messages(self.tls_session, symbols)
            if symbols == {"TLSHardCodedFinished"}:
                raw_client_finished = b"\x16\x03\x01\x00\x40" + (b"\xff" * 64)
                self.tls_session.socket.send(raw_client_finished)
            else:
                self.tls_session.flush_records()
        except BrokenPipeError:
            return "EOF"
        except ConnectionResetError:
            return "EOF"
        # pylint: disable=broad-except
        except Exception:
            return "INTERNAL ERROR DURING EMISSION"

        # Possible shortcut
        if expected_output == "No RSP":
            if self.options.expected_minimal_timeout > 0:
                real_timeout = min(
                    self.options.expected_minimal_timeout, self.options.timeout
                )
            else:
                return "No RSP"
        else:
            real_timeout = self.options.timeout

        # Read the answer
        try:
            response = read_next_msg(self.tls_session, timeout=real_timeout)
            if response is None:
                return "EOF"
            if not response:
                return "No RSP"

            while expected_output is None or expected_output != "+".join(response):
                next_msg = read_next_msg(self.tls_session, timeout=self.options.timeout)
                if not next_msg:  # Covers next_msg is None and next_msg = []
                    break
                response += next_msg
            return "+".join(response)
        # pylint: disable=broad-except
        except Exception:
            return "INTERNAL ERROR DURING RECEPTION"


def log_fn(log_file, s):
    print(s, end="")
    sys.stdout.flush()
    log_file.write(s)


def main():
    args = tls_args.parse_args(client_inference=False)

    try:
        os.mkdir(args.output_dir)
    except FileExistsError:
        pass
    log_filename = f"{args.output_dir}/infer_server.log"
    log_file = open(log_filename, "w", encoding="utf-8")
    log = lambda s: log_fn(log_file, s)
    args.log = log

    dirname = os.path.dirname(sys.argv[0])
    with open(
        f"{dirname}/../scenarios/{args.vocabulary}-client.scenario",
        "r",
        encoding="utf-8",
    ) as scenario_file:
        crypto_material_names = [name for name in args.crypto_material.iter_names()]
        scenario = config.scenarios.load_scenario(scenario_file, crypto_material_names)
    if scenario.role != "client":
        raise Exception("Invalid scenario (expecting a client role)")

    TLSBase = TLSServerKnowledgeBase(scenario.tls_version, options=args)

    logging.getLogger("WpMethodEQ").setLevel(logging.DEBUG)
    logging.getLogger("RandomWalkMethod").setLevel(logging.DEBUG)
    logging.getLogger("BDistMethod").setLevel(logging.DEBUG)
    logging.getLogger("HappyPathFirst").setLevel(logging.DEBUG)
    logging.getLogger("StoreHypotheses").setLevel(logging.DEBUG)

    try:
        TLSBase.start()

        if args.messages:
            input_sequence = Word(letters=[Letter(m) for m in args.messages])
            output_sequence = TLSBase._resolve_word(input_sequence)
            output = [list(l.symbols)[0] for l in output_sequence.letters]
            last_output = output
            repetitions = 1

            for sent, received in zip(args.messages, output):
                print(f"{sent} => {received}")
            sys.stdout.flush()

            for _i in range(1, args.loops):
                output_sequence = TLSBase._execute_word(input_sequence)
                output = [list(l.symbols)[0] for l in output_sequence.letters]

                if output == last_output:
                    repetitions += 1
                    continue

                print(f"    sequence observed {repetitions} times\n")
                repetitions = 1
                last_output = output

                for sent, received in zip(args.messages, output):
                    print(f"{sent} => {received}")
                sys.stdout.flush()

            if args.loops > 1:
                print(f"    sequence observed {repetitions} times\n")

            return

        input_letters = [Letter(s) for s in scenario.input_vocabulary]
        log(f"input_letters {scenario.input_vocabulary}\n")
        log(f"eqtests: {args.eq_method_str}\n")
        log(f"timeout: {args.timeout}\n")

        eqtests = args.eq_method((TLSBase, input_letters))
        if not args.disable_happy_path_first and scenario.interesting_paths:
            interesting_paths_with_letters = [
                [Letter(s) for s in path] for path in scenario.interesting_paths
            ]
            eqtests = HappyPathFirst(TLSBase, interesting_paths_with_letters, eqtests)
        eqtests = StoreHypotheses(
            TLSBase,
            scenario.input_vocabulary,
            args.output_dir,
            eqtests,
        )

        lstar = LSTAR(
            scenario.input_vocabulary, TLSBase, max_states=15, eqtests=eqtests
        )
        start = time.time()
        state_machine = lstar.learn()
        end = time.time()

        duration = end - start
        log(f"\ntime spent in lstar.learn(): {duration}\n")
        log(f"n_states: {len(state_machine.get_states())}\n")
    finally:
        TLSBase.stop()

    automaton = convert_from_pylstar(scenario.input_vocabulary, state_machine)
    with open(f"{args.output_dir}/final.automaton", "w", encoding="utf-8") as fd:
        fd.write(f"{automaton}\n")

    log(f"n_queries={TLSBase.stats.nb_query}\n")
    log(f"n_submitted_queries={TLSBase.stats.nb_submited_query}\n")
    log(f"n_letters={TLSBase.stats.nb_letter}\n")
    log(f"n_submitted_letters={TLSBase.stats.nb_submited_letter}\n")


if __name__ == "__main__":
    main()
