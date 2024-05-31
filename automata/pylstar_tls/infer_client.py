#!/usr/bin/env python

import os
import os.path
import sys
import time
import socket
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
from stubs.server_concretization import InfererTools
from automata.automata import convert_from_pylstar


class TLSClientKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, tls_version, options):
        super().__init__()

        # TODO: Should be checked earlier
        if options.crypto_material.default_material() == (None, None):
            raise Exception("Missing crypto material")

        if options.trigger_endpoint:
            accept_timeout = options.timeout
        else:
            accept_timeout = None

        self.tools = InfererTools(
            options.local_endpoint,
            options.crypto_material,
            options.timeout,
            accept_timeout,
        )
        self.tls_version = tls_version
        self.broken_client = False
        self.client_trigger = None
        self.tls_session = None
        self.options = options

    def start(self):
        if self.options.trigger_endpoint:
            endpoint_tuple = self.options.trigger_endpoint.as_tuple()
            self.client_trigger = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_trigger.connect(endpoint_tuple)

        # Start TLS server
        self.tls_session = self.tools.initTLS13Connexion()

    def stop(self):
        if self.client_trigger:
            self.client_trigger.close()

    def start_target(self):
        pass

    def stop_target(self):
        if self.tls_session.socket:
            self.tls_session.socket.close()

    def trigger_client(self):
        host, port = self.options.local_endpoint.as_tuple()
        trigger_string = f"{host} {port}\n".encode("utf8")
        if self.client_trigger:
            self.client_trigger.send_and_receive(trigger_string)
            try:
                _ = self.client_trigger.recv(8192, socket.MSG_DONTWAIT)
            except BlockingIOError:
                pass

    def accept_connection(self):
        try:
            self.tls_session.WAITING_CLIENT()
        except socket.timeout:
            return False

        self.tls_session.INIT_TLS_SESSION()
        if self.tls_version == "tls13":
            self.tls_session.tls13_handle_ClientHello()
        else:
            self.tls_session.tls12_handle_ClientHello()

        return True

    def submit_word(self, word):
        n = len(word.letters)

        if self.broken_client:
            letters = fill_answer_with([], "NO_CONNECTION", n)
            return Word(letters=letters)

        expected_letters = get_expected_output(word, self.knowledge_tree)
        if len(expected_letters) == n:
            return Word(letters=expected_letters)

        self.trigger_client()
        if not self.accept_connection():
            self.broken_client = True
            letters = fill_answer_with([], "NO_CONNECTION", n)
            return Word(letters=letters)

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
            self.tools.concretize_server_messages(self.tls_session, symbols)
            self.tls_session.flush_records(symbols)
        except BrokenPipeError:
            return "EOF"
        except ConnectionResetError:
            return "EOF"
        # pylint: disable=broad-except
        except Exception:
            return "INTERNAL ERROR DURING EMISSION"

        # Possible shortcut
        if expected_output is not None and expected_output == "No RSP":
            return "No RSP"

        # Read the answer
        try:
            response = read_next_msg(self.tls_session)
            if response is None:
                return "EOF"
            if not response:
                return "No RSP"

            while expected_output is None or expected_output != "+".join(response):
                next_msg = read_next_msg(self.tls_session)
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
    args = tls_args.parse_args(client_inference=True)

    try:
        os.mkdir(args.output_dir)
    except FileExistsError:
        pass
    log_filename = f"{args.output_dir}/infer_client.log"
    log_file = open(log_filename, "w", encoding="utf-8")
    log = lambda s: log_fn(log_file, s)
    args.log = log

    dirname = os.path.dirname(sys.argv[0])
    with open(
        f"{dirname}/../scenarios/{args.vocabulary}-server.scenario",
        "r",
        encoding="utf-8",
    ) as scenario_file:
        crypto_material_names = [name for name in args.crypto_material.iter_names()]
        scenario = config.scenarios.load_scenario(scenario_file, crypto_material_names)
    if scenario.role != "server":
        raise Exception("Invalid scenario (expecting a client role)")

    TLSBase = TLSClientKnowledgeBase(scenario.tls_version, options=args)

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
