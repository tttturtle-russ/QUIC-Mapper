#!/usr/bin/env python

import os
import os.path
import sys
import time
import logging

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
from automata.automata import convert_from_pylstar
from logger import QuicFileLogger , QuicLogger
from stubs.client_concretization import QUICClientInferTool


class QUICServerKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, configuration, dst_addr, local_addr, handle, options):
        super().__init__()
        self.configuration = configuration
        self.dst_addr = dst_addr
        self.local_addr = local_addr
        self.tool = QUICClientInferTool(configuration, dst_addr, local_addr, handle)
        self.options = options
        self.learned = False
        self.CC = False

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
            # if e == '<Epoch.INITIAL: 0>' or e == '<Epoch.HANDSHAKE: 2>' or e == '<Epoch.ONE_RTT: 3>':
            # return "EOF"
            # pass
            # else:
            print(e)
            return "INTERNAL ERROR DURING EMISSION"

        if self.tool.protocol.datagram_received() is not None:
            return "TIMEOUT"
        last_events = self.tool.logger.last_events()

        try:
            event = last_events.pop(0)
            data = event["data"]
            tmp = f"{data['header']['packet_type']}_{':'.join(frame['frame_type'] for frame in data['frames'])}"
            if 'ping' in tmp:
                return ''
            if "CC" in tmp:
                self.CC = True
                return "CC"
            response = [f"{data['header']['packet_type']}_{':'.join(frame['frame_type'] for frame in data['frames'])}"]
            # if response == '1RTT_ping:padding':
            #     response = []
            #     return ''
        except IndexError:
            return ""

        for event in last_events:
            # if expected_output is not None:
            #     break
            # if "+".join(response) == expected_output:
            #     return expected_output
            data = event["data"]
            tmp = f"{data['header']['packet_type']}_{':'.join(frame['frame_type'] for frame in data['frames'])}"
            if tmp == '1RTT_ping:padding':
                continue
            if "CC" in tmp:
                self.CC = True
                return "CC"
            # response.append(
            #     f"{data['header']['packet_type']}_{':'.join(frame['frame_type'] for frame in data['frames'])}"
            # )
            else:
                response.append(tmp)

        print("+".join(response))
        return "+".join(response)

    def reset(self):
        # handle = Handle(configuration=self.configuration)
        # self.tool = QUICClientInferTool(self.configuration, self.dst_addr, self.local_addr, handle)
        self.tool.reset()
        self.CC = False
        print('reset')


    def close(self):
        self.tool.close()


# class TLSServerKnowledgeBase(ActiveKnowledgeBase):
#     def __init__(self, tls_version, options):
#         super().__init__()
#         self.tools = InfererTools(
#             options.remote_endpoint,
#             options.crypto_material,
#             tls_version,
#         )
#         self.tls_session = None
#         self.options = options
#
#     def start(self):
#         pass
#
#     def stop(self):
#         pass
#
#     def start_target(self):
#         pass
#
#     def stop_target(self):
#         if self.tls_session:
#             self.tls_session.stop()
#
#     def submit_word(self, word):
#         n = len(word.letters)
#
#         expected_letters = get_expected_output(word, self.knowledge_tree)
#         if len(expected_letters) == n:
#             return Word(letters=expected_letters)
#
#         self.tls_session = self.tools.get_tls_session()
#
#         output_letters = []
#         for i in range(n):
#             if self.options.verbose:
#                 msg_to_send = "+".join(list(word.letters[i].symbols))
#                 self.options.log(msg_to_send)
#
#             expected_letter = None
#             if expected_letters:
#                 expected_letter = expected_letters.pop(0)
#
#             output_letter = self.send_and_receive(
#                 expected_letter, word.letters[i].symbols
#             )
#
#             if self.options.verbose:
#                 self.options.log(f" => {output_letter}\n")
#
#             output_letters.append(Letter(output_letter))
#             if output_letter == "EOF":
#                 output_letters = fill_answer_with(output_letters, "EOF", n)
#                 break
#
#         if self.options.verbose:
#             self.options.log("\n")
#         return Word(letters=output_letters)
#
#     def send_and_receive(self, expected_output, symbols):
#         try:
#             self.tools.concretize_client_messages(self.tls_session, symbols)
#             if symbols == {"TLSHardCodedFinished"}:
#                 raw_client_finished = b"\x16\x03\x01\x00\x40" + (b"\xff" * 64)
#                 self.tls_session.socket.send_and_receive(raw_client_finished)
#             else:
#                 self.tls_session.flush_records()
#         except BrokenPipeError:
#             return "EOF"
#         except ConnectionResetError:
#             return "EOF"
#         # pylint: disable=broad-except
#         except Exception:
#             return "INTERNAL ERROR DURING EMISSION"
#
#         # Possible shortcut
#         if expected_output == "No RSP":
#             if self.options.expected_minimal_timeout > 0:
#                 real_timeout = min(
#                     self.options.expected_minimal_timeout, self.options.timeout
#                 )
#             else:
#                 return "No RSP"
#         else:
#             real_timeout = self.options.timeout
#
#         # Read the answer
#         try:
#             response = read_next_msg(self.tls_session, timeout=real_timeout)
#             if response is None:
#                 return "EOF"
#             if not response:
#                 return "No RSP"
#
#             while expected_output is None or expected_output != "+".join(response):
#                 next_msg = read_next_msg(self.tls_session, timeout=self.options.timeout)
#                 if not next_msg:  # Covers next_msg is None and next_msg = []
#                     break
#                 response += next_msg
#             return "+".join(response)
#         # pylint: disable=broad-except
#         except Exception:
#             return "INTERNAL ERROR DURING RECEPTION"


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
            f"./scenarios/test.scenario",
            "r",
            encoding="utf-8",
    ) as scenario_file:
        #     crypto_material_names = [name for name in args.crypto_material.iter_names()]
        scenario = config.scenarios.load_scenario(scenario_file)
    # if scenario.role != "client":
    #     raise Exception("Invalid scenario (expecting a client role)")

    # TLSBase = TLSServerKnowledgeBase(scenario.tls_version, options=args)

    SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "dummy.ca.crt")
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]  # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=SERVER_CACERTFILE)  # CA certificate can be changed
    # quic_logger = QuicFileLogger(os.getcwd())
    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    local_addr = "172.17.0.1"
    QUICBase = QUICServerKnowledgeBase(configuration, ("172.17.0.2", 4433), ("172.17.0.1", 10011), handle, options=args)

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
    automaton = convert_from_pylstar(scenario.input_vocabulary, state_machine)
    with open(f"{args.output_dir}/final.automaton", "w", encoding="utf-8") as fd:
        fd.write(f"{automaton}\n")

    log(f"n_queries={QUICBase.stats.nb_query}\n")
    log(f"n_submitted_queries={QUICBase.stats.nb_submited_query}\n")
    log(f"n_letters={QUICBase.stats.nb_letter}\n")
    log(f"n_submitted_letters={QUICBase.stats.nb_submited_letter}\n")


if __name__ == "__main__":
    main()
