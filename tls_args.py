"""This modules contains the common code to handle arguments for TLS
inference tools."""

import sys
import argparse
from pylstar.eqtests.RandomWalkMethod import RandomWalkMethod
from pylstar.eqtests.WpMethodEQ import WpMethodEQ
from BDistMethod import BDistMethod
# from utils import Endpoint, CryptoMaterial, InvalidCryptoMaterialLine


# def handle_endpoint(parser, endpoint_str: str) -> Endpoint:
#     endpoint = Endpoint(endpoint_str)
#     if not endpoint.check():
#         print(f"Unable to resolve {endpoint}", file=sys.stderr)
#         parser.print_usage(file=sys.stderr)
#         sys.exit(1)
#     return endpoint
#
#
# def handle_crypto_material(parser, crypto_material_list):
#     crypto_material = CryptoMaterial()
#
#     for line in crypto_material_list:
#         try:
#             crypto_material.add(line)
#         except InvalidCryptoMaterialLine:
#             print(
#                 "Crypto material should be specified as name:cert:key[:DEFAULT].",
#                 file=sys.stderr,
#             )
#             parser.print_usage(file=sys.stderr)
#             sys.exit(1)
#
#     return crypto_material
#
#
def handle_eq_method(parser, eq_method_str):
    elts = eq_method_str.split(":")
    if len(elts) == 2 and elts[0] == "WP":
        max_states = int(elts[1])
        eq_method = lambda x: WpMethodEQ(x[0], max_states, x[1])
        return eq_method, f"WPMethod({max_states})"
    if len(elts) == 3 and elts[0] == "RW":
        nb_steps = int(elts[1])
        reset_proba = float(elts[2])
        eq_method = lambda x: RandomWalkMethod(x[0], x[1], nb_steps, reset_proba)
        return eq_method, f"RandomWalk({nb_steps}, {reset_proba})"
    if len(elts) == 2 and elts[0] == "BDist":
        distinguishing_bound = int(elts[1])
        eq_method = lambda x: BDistMethod(x[0], x[1], distinguishing_bound)
        return eq_method, f"BDist({distinguishing_bound})"
    print(f"Invalid Equivalence Method ({eq_method_str})", file=sys.stderr)
    parser.print_usage(file=sys.stderr)
    sys.exit(1)


def parse_args(client_inference):
    parser = argparse.ArgumentParser(
        description="Infer the state machine of a TLS implementation."
    )

    parser.add_argument(
        "-T",
        "--trigger-endpoint",
        action="store",
        type=str,
        dest="trigger_endpoint_str",
        default=None,
        help="address of the trigger (default is None)",
    )

    parser.add_argument(
            "-L",
            "--local-endpoint",
            action="store",
            type=str,
            dest="local_endpoint_str",
            default="127.0.0.1:4433",
            help="address used to accept connections (default is 127.0.0.1:4433)",
    )
    parser.add_argument(
            "-R",
            "--remote-endpoint",
            action="store",
            type=str,
            dest="remote_endpoint_str",
            default="127.0.0.1:4433",
            help="address to connect to (default is 127.0.0.1:4433)",
    )

    parser.add_argument(
        "-C",
        "--crypto-material",
        action="append",
        dest="crypto_material_list",
        help="crypto material name:certificate:key[:default]",
        default=[],
    )

    parser.add_argument(
        "--timeout",
        action="store",
        type=float,
        dest="timeout",
        default=1.0,
        help="the timeout in seconds to use for network communications (default is 1)",
    )

    parser.add_argument(
        "--expected-minimal-timeout",
        action="store",
        type=float,
        dest="expected_minimal_timeout",
        default=0.0,
        help="always wait a minimal timeout even with the expected optimization (default is 0)",
    )

    def_eq_test = "WP:7"
    parser.add_argument(
        "-E",
        "--eq-method",
        action="store",
        type=str,
        dest="eq_method_str",
        default=def_eq_test,
        help=f"equivalence method [WP:<states> or RW:<steps>:<reset_proba>] (default is {def_eq_test})",
    )
    parser.add_argument(
        "--disable-happy-path-first",
        action="store_true",
        dest="disable_happy_path_first",
        default=False,
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        action="store",
        type=str,
        dest="output_dir",
        default="/tmp/quic-infer",
        help="output directory where to write the state machines (default is /tmp/quic-infer)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        default=False,
        help="activate debug messages",
    )

    parser.add_argument(
        "-S",
        "--scenario",
        action="store",
        type=str,
        dest="scenario",
        default="tls12",
        help="the scenario used (default is tls12)",
    )

    parser.add_argument(
        "--loops",
        action="store",
        type=int,
        dest="loops",
        default=1,
        help="the number of times to send the messages (default is 1)",
    )

    parser.add_argument(
        '--cert',
        action='store',
        type=str,
        dest='cert',
        default=None,
        help='Certificate file'
    )

    parser.add_argument(
        '--port',
        action='store',
        type=int,
        dest='local_port',
        default=2000,
        help='Port to listen start'
    )

    parser.add_argument(
        "messages", metavar="messages", nargs="*", help="Sequence of messages to send"
    )

    args = parser.parse_args()

    result = argparse.Namespace()
    result.output_dir = args.output_dir
    result.verbose = args.verbose
    result.loops = args.loops
    result.messages = args.messages
    result.timeout = args.timeout
    result.cert = args.cert
    result.local_port = args.local_port
    result.expected_minimal_timeout = args.expected_minimal_timeout
    result.remote_addr = args.remote_endpoint_str
    result.local_addr = args.local_endpoint_str
    result.trigger_endpoint = None
    # if args.trigger_endpoint_str:
    #     result.trigger_endpoint = handle_endpoint(parser, args.trigger_endpoint_str)
    # else:
    #     result.trigger_endpoint = None
    #
    # if client_inference:
    #     result.local_endpoint = handle_endpoint(parser, args.local_endpoint_str)
    # else:
    #     result.remote_endpoint = handle_endpoint(parser, args.remote_endpoint_str)
    #
    # result.crypto_material = handle_crypto_material(parser, args.crypto_material_list)
    #
    # result.disable_happy_path_first = args.disable_happy_path_first
    result.eq_method, result.eq_method_str = handle_eq_method(
        parser, args.eq_method_str
    )

    # TODO!
    # Scenario = vocabulary + TLS version + Ciphersuites + Cert required?
    result.vocabulary = args.scenario

    return result
