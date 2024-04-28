#!/usr/bin/env python

import sys
from automata.automata import Automaton, load_automaton_from_file, message_was_not_sent
from automata.vulnerabilities import find_bb_oracle, color_bb_oracle, find_loops

# from config.scenarios import load_scenario


tls12_client_input_mapping = {
    "TLS12ServerHello": "SH",
    "TLS12CertificateRequest": "CR",
    "TLS12Certificate_valid": "Cert",
    "TLS12Certificate_invalid": "Cert_invalid",
    "TLS12Certificate_untrusted": "Cert_untrusted",
    "TLS12EmptyCertificate": "EmptyCert",
    "TLS12ServerKeyExchange": "SKE",
    "TLS12ServerHelloDone": "SHD",
    "TLSChangeCipherSpec": "CCS",
    "TLSFinished": "Fin",
    "TLSApplicationData": "AppData",
    "TLSCloseNotify": "Close",
}

tls12_client_output_mapping = {
    "FatalAlert(bad_record_mac)": "BadMAC",
    "FatalAlert(decode_error)": "DecodeError",
    "FatalAlert(handshake_failure)": "HSFailure",
    "FatalAlert(internal_error)": "InternalError",
    "FatalAlert(unexpected_message)": "UnexpMsg",
    "FatalAlert(unknown_ca)": "UnknwonCA",
    "FatalAlert(bad_certificate)": "BadCert",
    "INTERNAL ERROR DURING EMISSION": "COULDNOTEMIT",
    "NO_CONNECTION": "NOCONNECTION",
    "No RSP": "-",
    "TLSApplicationData": "AppData",
    "TLSCertificate": "Cert",
    "TLSCertificateVerify": "CV",
    "TLSChangeCipherSpec": "CCS",
    "TLSClientKeyExchange": "CKE",
    "TLSFinished": "Fin",
    "UnknownPacket": "UNKNOWN",
    "Warning(close_notify)": "Close",
}

tls13_client_input_mapping = {
    "TLS13ServerHello": "SH",
    "TLS13SH_WITH_00_RandBytes": "SH_rand00",
    "TLSChangeCipherSpec": "CCS",
    "TLS13EncryptedExtensions": "EE",
    "TLS13CertificateRequest": "CR",
    "TLS13Certificate_valid": "Cert",
    "TLS13Certificate_invalid": "Cert_invalid",
    "TLS13Certificate_untrusted": "Cert_untrusted",
    "TLS13EmptyCertificate": "EmptyCert",
    "TLS13CertificateVerify": "CV",
    "TLS13InvalidCertificateVerify": "CV_invalid",
    "TLSFinished": "Fin",
    "TLSApplicationData": "AppData",
    "TLSApplicationDataEmpty": "EmptyAppData",
    "TLSCloseNotify": "Close",
    "NoRenegotiation": "NoReneg",
}

tls13_client_output_mapping = {
    "FatalAlert(bad_record_mac)": "BadMAC",
    "FatalAlert(decode_error)": "DecodeError",
    "FatalAlert(handshake_failure)": "HSFailure",
    "FatalAlert(internal_error)": "InternalError",
    "FatalAlert(unexpected_message)": "UnexpMsg",
    "FatalAlert(unknown_ca)": "UnknwonCA",
    "FatalAlert(certificate_required)": "CertRequires",
    "FatalAlert(certificate_unknown)": "CertUnknown",
    "FatalAlert(close_notify)": "FatalClose",
    "FatalAlert(decrypt_error)": "DecryptError",
    "FatalAlert(decryption_failed)": "DecryptFailed",
    "FatalAlert(illegal_parameter)": "IllegalParam",
    "FatalAlert(protocol_version)": "WrongVersion",
    "FatalAlert(bad_certificate)": "BadCert",
    "INTERNAL ERROR DURING EMISSION": "COULDNOTEMIT",
    "NO_CONNECTION": "NOCONNECTION",
    "No RSP": "-",
    "TLSApplicationData": "AppData",
    "TLS13Certificate": "Cert",
    "TLSCertificateVerify": "CV",
    "TLSChangeCipherSpec": "CCS",
    "TLSFinished": "Fin",
    "UnknownPacket": "UNKNOWN",
    "Warning(close_notify)": "Close",
}

tls10_tls12_server_input_mapping = {
    "NoRenegotiation": "NoReneg",
    "TLS12Certificate_valid": "Cert",
    "TLS12Certificate_untrusted": "Cert_untrusted",
    "TLS12CH_WITH_00_RandBytes": "CH_rand00",
    "TLS12ClientHelloDH": "CH_DHE",
    "TLS12ClientHelloRSA": "CH_RSA",
    "TLS12ClientKeyExchange": "CKE",
    "TLS12EmptyCertificate": "EmptyCert",
    "TLSApplicationData": "AppData",
    "TLSApplicationDataEmpty": "EmptyAppData",
    "TLSCertificateVerify": "CV",
    "TLSChangeCipherSpec": "CCS",
    "TLSCloseNotify": "Close",
    "TLSFinished": "Fin",
}

tls10_tls12_server_output_mapping = {
    "FatalAlert(bad_record_mac)": "BadMAC",
    "FatalAlert(decode_error)": "DecodeError",
    "FatalAlert(decryption_failed)": "DecryptFailed",
    "FatalAlert(handshake_failure)": "HSFailure",
    "FatalAlert(internal_error)": "InternalError",
    "FatalAlert(no_renegotiation)": "FatalNoReneg",
    "FatalAlert(unexpected_message)": "UnexpMsg",
    "FatalAlert(illegal_parameter)": "IllegalParam",
    "FatalAlert(bad_certificate)": "BadCert",
    "FatalAlert(unknown_ca)": "UnknwonCA",
    "No RSP": "-",
    "TLSApplicationData": "AppData",
    "TLSCertificate": "Cert",
    "TLSCertificateRequest": "CR",
    "TLSChangeCipherSpec": "CCS",
    "TLSFinished": "Fin",
    "TLSServerHello": "SH",
    "TLSServerHelloDone": "SHD",
    "TLSServerKeyExchange": "SKE",
    "UnknownPacket": "UNKNOWN",
    "Warning(close_notify)": "Close",
    "Warning(no_renegotiation)": "NoReneg",
}

tls13_server_input_mapping = {
    "NoRenegotiation": "NoReneg",
    "TLS13Certificate_valid": "Cert",
    "TLS13Certificate_untrusted": "Cert_untrusted",
    "TLS13ClientHello": "CH",
    "TLS13EmptyCertificate": "EmptyCert",
    "TLSApplicationData": "AppData",
    "TLSApplicationDataEmpty": "EmptyAppData",
    "TLSCertificateVerify": "CV",
    "TLSCloseNotify": "Close",
    "TLSFinished": "Fin",
    "TLSInvalidCertificateVerify": "CV_invalid",
}

tls13_server_output_mapping = {
    "FatalAlert(bad_record_mac)": "BadMAC",
    "FatalAlert(decode_error)": "DecodeError",
    "FatalAlert(handshake_failure)": "HSFailure",
    "FatalAlert(internal_error)": "InternalError",
    "FatalAlert(unexpected_message)": "UnexpMsg",
    "FatalAlert(unknown_ca)": "UnknwonCA",
    "FatalAlert(certificate_required)": "CertRequires",
    "FatalAlert(certificate_unknown)": "CertUnknown",
    "FatalAlert(close_notify)": "FatalClose",
    "FatalAlert(decrypt_error)": "DecryptError",
    "FatalAlert(decryption_failed)": "DecryptFailed",
    "FatalAlert(illegal_parameter)": "IllegalParam",
    "FatalAlert(protocol_version)": "WrongVersion",
    "No RSP": "-",
    "TLSEncryptedExtensions": "EE",
    "TLSApplicationData": "AppData",
    "TLS13Certificate": "Cert",
    "TLS13CertificateRequest": "CR",
    "TLS13NewSessionTicket": "NST",
    "TLSCertificateVerify": "CV",
    "TLSChangeCipherSpec": "CCS",
    "TLS13ServerHello": "SH",
    "TLSFinished": "Fin",
    "UnknownPacket": "UNKNOWN",
    "Warning(close_notify)": "Close",
}

tls_fatal_alerts_as_eof = {
    "BadMAC": "EOF",
    "DecodeError": "EOF",
    "HSFailure": "EOF",
    "InternalError": "EOF",
    "UnexpMsg": "EOF",
    "UnknwonCA": "EOF",
    "CertRequires": "EOF",
    "CertUnknown": "EOF",
    "FatalClose": "EOF",
    "DecryptError": "EOF",
    "DecryptFailed": "EOF",
    "IllegalParam": "EOF",
    "WrongVersion": "EOF",
    "FatalNoReneg": "EOF",
    "BadCert": "EOF",
    "UnknownCA": "EOF",
}

mappings = {
    "client.tls12": [tls12_client_input_mapping, tls12_client_output_mapping],
    "client.tls13": [tls13_client_input_mapping, tls13_client_output_mapping],
    "server.tls10": [
        tls10_tls12_server_input_mapping,
        tls10_tls12_server_output_mapping,
    ],
    "server.tls10-auth": [
        tls10_tls12_server_input_mapping,
        tls10_tls12_server_output_mapping,
    ],
    "server.bb-oracle": [
        tls10_tls12_server_input_mapping,
        tls10_tls12_server_output_mapping,
    ],
    "server.tls12": [
        tls10_tls12_server_input_mapping,
        tls10_tls12_server_output_mapping,
    ],
    "server.tls12-auth": [
        tls10_tls12_server_input_mapping,
        tls10_tls12_server_output_mapping,
    ],
    "server.tls13": [tls13_server_input_mapping, tls13_server_output_mapping],
    "server.tls13-auth": [tls13_server_input_mapping, tls13_server_output_mapping],
}


# Simple tests on automata


def is_client_answering(automaton):
    return automaton.contains_transition_with_received_msg("TLSClientKeyExchange")


def is_client_working(automaton):
    return automaton.contains_transition_with_received_msg("Fin")


def is_server_answering(automaton):
    return automaton.contains_transition_with_received_msg("SH")


def is_server_working(automaton):
    return automaton.contains_transition_with_received_msg("Fin")


working_tests = {
    "client.tls12": is_client_working,
    "client.tls13": is_client_working,
    "client.freak": is_client_answering,
    "server.tls10": is_server_working,
    "server.tls12": is_server_working,
    "server.tls13": is_server_working,
    "server.tls10-auth": is_server_working,
    "server.tls12-auth": is_server_working,
    "server.tls13-auth": is_server_working,
    "server.bb-oracle": is_server_answering,
}


# Happy paths

server_tls10_tls12_happy_paths = [
    [("CH_RSA", set()), ("CKE", set()), ("CCS", set()), ("Fin", {"Fin"})],
    [("CH_DHE", set()), ("CKE", set()), ("CCS", set()), ("Fin", {"Fin"})],
    [
        ("CH_RSA", set()),
        ("CKE", set()),
        ("CCS", set()),
        ("Fin", {"Fin"}),
        ("AppData", []),
    ],
    [
        ("CH_DHE", set()),
        ("CKE", set()),
        ("CCS", set()),
        ("Fin", {"Fin"}),
        ("AppData", []),
    ],
]

server_tls10_tls12_auth_happy_paths = [
    [
        ("CH_RSA", set()),
        ("Cert", set()),
        ("CKE", set()),
        ("CV", set()),
        ("CCS", set()),
        ("Fin", {"Fin"}),
    ],
    [
        ("CH_DHE", set()),
        ("Cert", set()),
        ("CKE", set()),
        ("CV", set()),
        ("CCS", set()),
        ("Fin", {"Fin"}),
    ],
    [
        ("CH_RSA", set()),
        ("CKE", set()),
        ("CCS", set()),
        ("Fin", {"Fin"}),
        ("AppData", []),
    ],
    [
        ("CH_DHE", set()),
        ("CKE", set()),
        ("CCS", set()),
        ("Fin", {"Fin"}),
        ("AppData", []),
    ],
]

happy_paths = {
    "client.tls12": [
        [
            ("SH", set()),
            ("Cert", set()),
            ("SKE", set()),
            ("SHD", {"Fin"}),
            ("CCS", set()),
            ("Fin", set()),
        ],
        [
            ("SH", set()),
            ("Cert", set()),
            ("SHD", {"Fin"}),
            ("CCS", set()),
            ("Fin", set()),
        ],
        [
            ("SH", set()),
            ("Cert", set()),
            ("SKE", set()),
            ("CR", set()),
            ("SHD", {"Fin"}),
            ("CCS", set()),
            ("Fin", set()),
        ],
        [
            ("SH", set()),
            ("Cert", set()),
            ("CR", set()),
            ("SHD", {"Fin"}),
            ("CCS", set()),
            ("Fin", set()),
        ],
        [
            ("SH", set()),
            ("Cert", set()),
            ("SKE", set()),
            ("SHD", {"Fin"}),
            ("CCS", set()),
            ("Fin", set()),
            ("AppData", []),
        ],
        [
            ("SH", set()),
            ("Cert", set()),
            ("SHD", {"Fin"}),
            ("CCS", set()),
            ("Fin", set()),
            ("AppData", set()),
        ],
    ],
    "client.tls13": [
        [
            ("SH", set()),
            ("CCS", set()),
            ("EE", set()),
            ("Cert", set()),
            ("CV", set()),
            ("Fin", {"Fin"}),
            ("AppData", set()),
        ],
        [
            ("SH", set()),
            ("EE", set()),
            ("Cert", set()),
            ("CV", set()),
            ("Fin", {"Fin"}),
            ("AppData", set()),
        ],
        [
            ("SH", set()),
            ("CCS", set()),
            ("EE", set()),
            ("Cert", set()),
            ("CV", set()),
            ("Fin", {"Fin"}),
        ],
        [
            ("SH", set()),
            ("EE", set()),
            ("Cert", set()),
            ("CV", set()),
            ("Fin", {"Fin"}),
        ],
    ],
    "server.tls10": server_tls10_tls12_happy_paths,
    "server.tls10-auth": server_tls10_tls12_auth_happy_paths,
    "server.tls12": server_tls10_tls12_happy_paths,
    "server.tls12-auth": server_tls10_tls12_auth_happy_paths,
    "server.tls13": [
        [("CH", {"Fin"}), ("Fin", set())],
        [("CH", {"Fin"}), ("Fin", set()), ("AppData", [])],
    ],
    "server.tls13-auth": [
        [("CH", {"Fin"}), ("Cert", set()), ("CV", set()), ("Fin", set())],
        [
            ("CH", {"Fin"}),
            ("Cert", set()),
            ("CV", set()),
            ("Fin", set()),
            ("AppData", []),
        ],
    ],
}


# Vulnerability tests


def is_server_vulnerable_to_bb_oracle(automaton):
    good_msgs = ["TLS12CKE_ok"]
    bad_msgs = list(
        filter(
            lambda m: m.startswith("TLS12CKE_") and m != "TLS12CKE_ok",
            automaton.input_vocabulary,
        )
    )

    interesting_states = find_bb_oracle(automaton, good_msgs, bad_msgs)
    if interesting_states:
        color_bb_oracle(automaton, good_msgs, bad_msgs, interesting_states)
        return "Possible BB oracle"
    return None


def detect_loops(automaton, crypto_msgs_str="CCS"):
    crypto_msgs = crypto_msgs_str.split("/")
    loops = find_loops(automaton, crypto_msgs)
    if loops:
        for loop in loops:
            automaton.color_path(loop, "orange")
        return f"Pre-{crypto_msgs} loops found"
    return None


def detect_dangerous_flaw_for_client_tls13(automaton):
    all_paths = automaton.enumerate_paths_until_recv_msg("AppData")
    vulnerable_paths = filter(lambda path: message_was_not_sent(path, "CV"), all_paths)
    vulnerable_paths = list(vulnerable_paths)
    if vulnerable_paths:
        for path in vulnerable_paths:
            automaton.color_path(path, "red")
        return "Possible authentication bypass"
    return None


def detect_dangerous_flaw_for_client_tls12(automaton):
    all_paths = automaton.enumerate_paths_until_recv_msg("AppData")
    vulnerable_paths = filter(lambda path: message_was_not_sent(path, "SKE"), all_paths)
    vulnerable_paths = list(vulnerable_paths)
    if vulnerable_paths:
        for path in vulnerable_paths:
            automaton.color_path(path, "red")
        return "Possible authentication bypass"
    return None


def detect_dangerous_flaw_for_server_tls(automaton):
    all_paths = automaton.enumerate_paths_until_recv_msg("AppData")
    vulnerable_paths = filter(lambda path: message_was_not_sent(path, "CV"), all_paths)
    vulnerable_paths = list(vulnerable_paths)
    if vulnerable_paths:
        for path in vulnerable_paths:
            automaton.color_path(path, "red")
        return "Possible authentication bypass"
    return None


security_tests = {
    "server.tls10": [detect_loops],
    "server.tls12": [detect_loops],
    "server.tls13": [lambda a: detect_loops(a, "CH/CH_rand00")],
    "server.tls10-auth": [detect_loops, detect_dangerous_flaw_for_server_tls],
    "server.tls12-auth": [detect_loops, detect_dangerous_flaw_for_server_tls],
    "server.tls13-auth": [
        lambda a: detect_loops(a, "CH/CH_rand00"),
        detect_dangerous_flaw_for_server_tls,
    ],
    "client.tls12": [detect_loops, detect_dangerous_flaw_for_client_tls12],
    "client.tls13": [
        lambda a: detect_loops(a, "SH/SH_rand00"),
        detect_dangerous_flaw_for_client_tls13,
    ],
    "server.bb-oracle": [is_server_vulnerable_to_bb_oracle],
}


# Automaton enumeration and manipulation


def cleanup_uninteresting_transitions(automaton):
    for state in automaton.states:
        for sent_msg in automaton.input_vocabulary:
            next_state, recv_msgs, colors = automaton.states[state][sent_msg]
            if colors:
                continue
            if not automaton.is_sink_state(next_state):
                continue
            if len(recv_msgs) != 1:
                continue
            if recv_msgs in [["Close"], ["EOF"]]:
                colors.add("grey")
            if recv_msgs[0] in tls_fatal_alerts_as_eof:
                colors.add("grey")


def usage(message: str):
    print(message, file=sys.stderr)
    print(
        f"Usage: {sys.argv[0]} scenario_file automaton_file dot_file", file=sys.stderr
    )
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        usage("Invalid arguments")

    # Step 1: load the scenario and the automaton

    # scenario = load_scenario(open(sys.argv[1]), [])
    # for happy_path in scenario.happy_paths:
    #     real_path = automaton.extract_happy_path(happy_path)
    #     if real_path:
    #         automaton.color_path(real_path, "green")
    scenario = sys.argv[1]
    automaton: Automaton = load_automaton_from_file(sys.argv[2])
    original_automaton_hash_value = automaton.compute_hash().hex()

    # Step 2: rename the messages using shorter names

    automaton = automaton.rename_input_vocabulary(mappings[scenario][0])
    automaton = automaton.rename_output_vocabulary(mappings[scenario][1])

    # Step 3 (optional): simplify the automaton by merging the alerts into EOF

    # if False:
    #     automaton = automaton.rename_output_vocabulary(tls_fatal_alerts_as_eof)
    #     automaton.minimize()

    # Step 4: happy paths

    if scenario in happy_paths:
        for happy_path in happy_paths[scenario]:
            real_path = automaton.extract_happy_path(happy_path)
            if real_path:
                automaton.color_path(real_path, "green")

    # Step 5: security tests

    security_results = []
    if scenario in security_tests:
        for test in security_tests[scenario]:
            result = test(automaton)
            if result:
                security_results.append(result)

    # Step 6: color the state machine and produce the dot content

    cleanup_uninteresting_transitions(automaton)

    def color_policy(colors):
        if "green" in colors:
            return {"green"}, False
        if colors == {"grey"}:
            return {"grey"}, True
        return colors, len(colors) == 0

    dot_content = automaton.dot(color_policy)
    with open(sys.argv[3], "w", encoding="utf-8") as dot_file:
        dot_file.write(dot_content)

    # Step 7: print metadata

    working = working_tests[scenario](automaton)
    processed_automaton_hash_value = automaton.compute_hash().hex()
    bdist_results = automaton.compute_bdist()

    print(f"Original automaton hash = {original_automaton_hash_value}")
    print(f"Processed automaton hash = {processed_automaton_hash_value}")
    print(f"The implementation seems to be working? {working}")
    print(f"Nb States = {len(automaton.states)}")
    print(f"BDist for this state machine = {bdist_results[0]}")
    security_results_str = "\n   ".join(security_results)
    print(f"Security results = {security_results_str}")


if __name__ == "__main__":
    main()
