#!/usr/bin/env python

import os
import os.path
import sys
import time
import logging
import ssl
import typing

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion
from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter
from pylstar.Word import Word

import config.scenarios
import tls_args
from receive_data import Handle
from utils import (
    fill_answer_with,
    get_expected_output,
)
from HappyPathFirst import HappyPathFirst
from StoreHypotheses import StoreHypotheses
# from stubs.client_concretization import InfererTools
from automata.automata import convert_from_pylstar, convert_from_pylstar_to_dot
from logger import QuicFileLogger , QuicLogger
from stubs.client_concretization import QUICClientInferTool


class QUICServerKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, configuration, dst_addr, local_addr, local_port, handle, options):
        super().__init__()
        self.configuration = configuration
        self.dst_addr = dst_addr
        self.local_addr = local_addr
        self.tool = QUICClientInferTool(configuration, dst_addr, local_addr, local_port, handle)
        self.options = options
        self.learned = False
        self.CC = False
        self.timeout_set = options.timeout
        self.timeout_real = self.timeout_set
        self.pre_msg = None

    def start(self):
        pass

    def stop(self):
        # self.tool.handle.end_trace_file()
        self.tool.handle.end_trace()
        self.close()


    def stop_target(self):
        pass

    def start_target(self):
        self.reset()
        # pass

    # def reset(self):
    #     handle = Handle(configuration=self.configuration)
    #     self.tool = QUICClientInferTool(self.configuration, self.dst_addr, self.local_addr, handle)

    def submit_word(self, word):

        # if not self.learned:
        # handle = Handle(configuration=self.configuration)
        # self.tool = QUICClientInferTool(self.configuration, self.dst_addr, self.local_addr, handle)
        # self.learned = True
        n = len(word.letters)

        expected_letters = get_expected_output(word, self.knowledge_tree)
        if len(expected_letters) == n:
            return Word(letters=expected_letters)

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
        # self.reset()
        return Word(letters=output_letters)

    def send_and_receive(self, expected_output, symbols):
        # start = time.time()
        # print('expected_output:', expected_output)
        if self.CC is True:
            return "CC"
        try:
            self.tool.concretize_client_messages(symbols)
        except BrokenPipeError:
            return "EOF"
        except ConnectionResetError:
            return "EOF"
        # pylint: disable=broad-except
        except Exception as e:
            if str(e) == 'Encryption key is not available':
                pass
            else:
                print(e)
                return "INTERNAL ERROR DURING EMISSION"

        if expected_output is not None and expected_output == "TIMEOUT":
            return "TIMEOUT"

        response = self.receive()
        if not response:
            return 'TIMEOUT'

        if response == 'ping':
            print('ping')
            response = ''

        start_time = time.time()
        while expected_output != response or expected_output is None:

            next_msg = self.receive()
            # if not next_msg:
            #     break
            if next_msg == 'ping':
                print('ping')
                next_msg = self.receive()
            if next_msg and next_msg != '' and next_msg != 'ping':
                if response != '':
                    response += '+' + next_msg
                else:
                    response = next_msg
            time_now = time.time()
            if time_now - start_time > self.timeout_set:
                next_msg = self.receive()
                # if not next_msg:
                #     break\
                if next_msg == 'ping':
                    print('ping')
                    next_msg = self.receive()
                if next_msg and next_msg != '' and next_msg != 'ping':
                    if response != '':
                        response += '+' + next_msg
                    else:
                        response = next_msg
                break
            # self.pre_msg = next_msg


        if not response or response == '':
            return 'TIMEOUT'

        # print("+".join(response))
        # print('response:', response)
        # return "+".join(response)
        return response

    def reset(self):
        # handle = Handle(configuration=self.configuration)
        # self.tool = QUICClientInferTool(self.configuration, self.dst_addr, self.local_addr, handle)
        self.tool.reset()
        self.CC = False
        print('-' * 20)
        print('-'*10 + ' reset '+'-'*10)



    def close(self):
        self.tool.close()

    def receive(self):
        msg = self.tool.protocol.datagram_received(timeout=self.timeout_set)

        if msg is None:
            # print('no data')
            return None
        # print('data yes')
        if 'CC' in msg:
            self.CC = True

        return msg

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

    # dirname = os.path.dirname(sys.argv[1])
    with open(
            f"./scenarios/test.scenario.old",
            "r",
            encoding="utf-8",
    ) as scenario_file:
        scenario = config.scenarios.load_scenario(scenario_file)

    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]  # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=None)  # CA certificate can be changed
    configuration.verify_mode = ssl.CERT_NONE  # important for client disable CA verification

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    local_ip, local_port = args.local_addr.split(':')
    local_port = int(local_port)

    dst_ip_add_str, dst_port_str = args.remote_addr.split(':')
    dst_port_int = int(dst_port_str)
    dst_addr = (dst_ip_add_str, dst_port_int)
    QUICBase = QUICServerKnowledgeBase(configuration, dst_addr, local_ip, local_port, handle, options=args)

    logging.getLogger("WpMethodEQ").setLevel(logging.DEBUG)
    logging.getLogger("RandomWalkMethod").setLevel(logging.DEBUG)
    logging.getLogger("BDistMethod").setLevel(logging.DEBUG)
    logging.getLogger("HappyPathFirst").setLevel(logging.DEBUG)
    logging.getLogger("StoreHypotheses").setLevel(logging.DEBUG)

    try:
        # TLSBase.start()
        QUICBase.start()

        if args.messages:
            input_sequence = Word(letters=[Letter(m) for m in args.messages])

            output_sequence = QUICBase._resolve_word(input_sequence)
            # output_sequence = TLSBase._resolve_word(input_sequence)

            output = [list(l.symbols)[0] for l in output_sequence.letters]
            last_output = output
            repetitions = 1

            for sent, received in zip(args.messages, output):
                print(f"{sent} => {received}")
            sys.stdout.flush()

            for _i in range(1, args.loops):
                # output_sequence = TLSBase._execute_word(input_sequence)
                output_sequence = QUICBase._execute_word(input_sequence)
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

            log(f"input_letters {args.messages}\n")
            log(f"eqtests: {args.eq_method_str}\n")
            log(f"timeout: {args.timeout}\n")

            eqtests = args.eq_method((QUICBase, args.messages))
            eqtests = StoreHypotheses(
                QUICBase,
                args.messages,
                args.output_dir,
                eqtests,
            )

            lstar = LSTAR(
                args.messages, QUICBase, max_states=15, eqtests=eqtests
            )

            start = time.time()
            state_machine = lstar.learn()
            end = time.time()

            duration = end - start
            log(f"\ntime spent in lstar.learn(): {duration}\n")
            log(f"n_states: {len(state_machine.get_states())}\n")

            QUICBase.stop()

            automaton = convert_from_pylstar(args.messages, state_machine)
            with open(f"{args.output_dir}/final.automaton", "w", encoding="utf-8") as fd:
                fd.write(f"{automaton}\n")

            log(f"n_queries={QUICBase.stats.nb_query}\n")
            log(f"n_submitted_queries={QUICBase.stats.nb_submited_query}\n")
            log(f"n_letters={QUICBase.stats.nb_letter}\n")
            log(f"n_submitted_letters={QUICBase.stats.nb_submited_letter}\n")

            return

        # input_letters = [s for s in scenario.input_vocabulary[1:]]
        input_letters = [Letter(s) for s in scenario.input_vocabulary]
        input_letters_str = [s for s in scenario.input_vocabulary]
        log(f"input_letters {scenario.input_vocabulary}\n")
        log(f"eqtests: {args.eq_method_str}\n")
        log(f"timeout: {args.timeout}\n")
        input_sequence = Word(letters=[Letter(s) for s in scenario.input_vocabulary])
        output_sequence = QUICBase._resolve_word(input_sequence)
        # output_sequence = TLSBase._resolve_word(input_sequence)
        output = [list(l.symbols)[0] for l in output_sequence.letters]
        last_output = output
        repetitions = 1
        print('-'*20)
        for sent, received in zip(input_letters, output):
            log(f"{sent} => {received}\n")
        sys.stdout.flush()

        eqtests = args.eq_method((QUICBase, input_letters))
        # eqtests = args.eq_method((TLSBase, input_letters))
        # if scenario.interesting_paths:
        #     interesting_paths_with_letters = [
        #         [Letter(s) for s in path] for path in scenario.interesting_paths
        #     ]
        #     eqtests = HappyPathFirst(QUICBase, interesting_paths_with_letters, eqtests)
        eqtests = StoreHypotheses(
            QUICBase,
            input_letters,
            args.output_dir,
            eqtests,
        )
        lstar = LSTAR(
            input_letters_str, QUICBase, max_states=15, eqtests=eqtests
        )
        start = time.time()
        state_machine = lstar.learn()
        end = time.time()
        duration = end - start
        log(f"\ntime spent in lstar.learn(): {duration}\n")
        log(f"n_states: {len(state_machine.get_states())}\n")
    finally:
        # TLSBase.stop()
        QUICBase.stop()
    automaton = convert_from_pylstar([Letter(s) for s in scenario.input_vocabulary], state_machine)
    with open(f"{args.output_dir}/final.automaton", "w", encoding="utf-8") as fd:
        fd.write(f"{automaton}\n")
    dot = convert_from_pylstar_to_dot([Letter(s) for s in scenario.input_vocabulary], state_machine)
    with open(f"{args.output_dir}/final.dot", "w", encoding="utf-8") as fd:
        fd.write(f"{dot}\n")

    log(f"n_queries={QUICBase.stats.nb_query}\n")
    log(f"n_submitted_queries={QUICBase.stats.nb_submited_query}\n")
    log(f"n_letters={QUICBase.stats.nb_letter}\n")
    log(f"n_submitted_letters={QUICBase.stats.nb_submited_letter}\n")


if __name__ == "__main__":
    main()
