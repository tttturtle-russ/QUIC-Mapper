from automata.automata import load_automaton

SERVER_AUTOMATON_CONTENT = """TLS13ClientHello TLSApplicationData TLSChangeCipherSpec TLSFinished
0, 1, TLS13ClientHello, TLS13ServerHello+TLSChangeCipherSpec+TLSEncryptedExtensions+TLS13Certificate+TLSCertificateVerify+TLSFinished
0, 3, TLSApplicationData, FatalAlert(unexpected_message)
0, 3, TLSChangeCipherSpec, FatalAlert(unexpected_message)
0, 3, TLSFinished, FatalAlert(unexpected_message)
1, 3, TLS13ClientHello, FatalAlert(unexpected_message)
1, 3, TLSApplicationData, FatalAlert(unexpected_message)
1, 3, TLSChangeCipherSpec, FatalAlert(unexpected_message)
1, 2, TLSFinished, TLS13NewSessionTicket+TLS13NewSessionTicket
2, 3, TLS13ClientHello, FatalAlert(unexpected_message)
2, 3, TLSApplicationData, TLSApplicationData
2, 3, TLSChangeCipherSpec, FatalAlert(unexpected_message)
2, 3, TLSFinished, FatalAlert(unexpected_message)
3, 3, TLS13ClientHello, EOF
3, 3, TLSApplicationData, EOF
3, 3, TLSChangeCipherSpec, EOF
3, 3, TLSFinished, EOF"""

# pylint: disable=line-too-long
CLIENT_AUTOMATON_CONTENT = """TLS13CertificateRequest TLS13CertificateVerify TLS13Certificate TLS13EncryptedExtensions TLS13ServerHello TLSApplicationData TLSFinished
0, 8, TLS13CertificateRequest, FatalAlert(unexpected_message)
0, 8, TLS13CertificateVerify, FatalAlert(unexpected_message)
0, 8, TLS13Certificate, FatalAlert(unexpected_message)
0, 8, TLS13EncryptedExtensions, FatalAlert(unexpected_message)
0, 1, TLS13ServerHello, No RSP
0, 8, TLSApplicationData, FatalAlert(unexpected_message)
0, 8, TLSFinished, FatalAlert(unexpected_message)
1, 8, TLS13CertificateRequest, FatalAlert(unexpected_message)
1, 8, TLS13CertificateVerify, FatalAlert(unexpected_message)
1, 8, TLS13Certificate, FatalAlert(unexpected_message)
1, 2, TLS13EncryptedExtensions, No RSP
1, 8, TLS13ServerHello, FatalAlert(unexpected_message)
1, 8, TLSApplicationData, FatalAlert(unexpected_message)
1, 8, TLSFinished, FatalAlert(unexpected_message)
2, 3, TLS13CertificateRequest, No RSP
2, 8, TLS13CertificateVerify, UnknownPacket
2, 4, TLS13Certificate, No RSP
2, 8, TLS13EncryptedExtensions, UnknownPacket
2, 8, TLS13ServerHello, UnknownPacket
2, 8, TLSApplicationData, UnknownPacket
2, 8, TLSFinished, UnknownPacket
3, 8, TLS13CertificateRequest, UnknownPacket
3, 8, TLS13CertificateVerify, UnknownPacket
3, 5, TLS13Certificate, No RSP
3, 8, TLS13EncryptedExtensions, UnknownPacket
3, 8, TLS13ServerHello, UnknownPacket
3, 8, TLSApplicationData, UnknownPacket
3, 8, TLSFinished, UnknownPacket
4, 8, TLS13CertificateRequest, UnknownPacket
4, 6, TLS13CertificateVerify, No RSP
4, 8, TLS13Certificate, UnknownPacket
4, 8, TLS13EncryptedExtensions, UnknownPacket
4, 8, TLS13ServerHello, UnknownPacket
4, 8, TLSApplicationData, UnknownPacket
4, 8, TLSFinished, UnknownPacket
5, 8, TLS13CertificateRequest, UnknownPacket
5, 7, TLS13CertificateVerify, No RSP
5, 8, TLS13Certificate, UnknownPacket
5, 8, TLS13EncryptedExtensions, UnknownPacket
5, 8, TLS13ServerHello, UnknownPacket
5, 8, TLSApplicationData, UnknownPacket
5, 8, TLSFinished, UnknownPacket
6, 8, TLS13CertificateRequest, UnknownPacket
6, 8, TLS13CertificateVerify, UnknownPacket
6, 8, TLS13Certificate, UnknownPacket
6, 8, TLS13EncryptedExtensions, UnknownPacket
6, 8, TLS13ServerHello, UnknownPacket
6, 8, TLSApplicationData, UnknownPacket
6, 8, TLSFinished, TLSFinished+Warning(close_notify)
7, 8, TLS13CertificateRequest, UnknownPacket
7, 8, TLS13CertificateVerify, UnknownPacket
7, 8, TLS13Certificate, UnknownPacket
7, 8, TLS13EncryptedExtensions, UnknownPacket
7, 8, TLS13ServerHello, UnknownPacket
7, 8, TLSApplicationData, UnknownPacket
7, 8, TLSFinished, TLS13Certificate+TLSFinished+Warning(close_notify)
8, 8, TLS13CertificateRequest, EOF
8, 8, TLS13CertificateVerify, EOF
8, 8, TLS13Certificate, EOF
8, 8, TLS13EncryptedExtensions, EOF
8, 8, TLS13ServerHello, EOF
8, 8, TLSApplicationData, EOF
8, 8, TLSFinished, EOF
"""


def test_bdist_server_automaton():
    automaton = load_automaton(SERVER_AUTOMATON_CONTENT)
    results = automaton.compute_bdist()
    assert results[0] == 1
    assert len(automaton.states) == 4
    assert len(results[1]) == 6


def test_bdist_client_automaton():
    automaton = load_automaton(CLIENT_AUTOMATON_CONTENT)
    results = automaton.compute_bdist()
    assert results[0] == 2
    assert len(results[1]) == 1
    assert list(results[1].values())[0] == ["TLS13CertificateVerify", "TLSFinished"]


def test_bdist_trivial_automaton():
    automaton = load_automaton("A\n0, 0, A,")
    results = automaton.compute_bdist()
    assert results[0] == 0
    assert len(results[1]) == 0
