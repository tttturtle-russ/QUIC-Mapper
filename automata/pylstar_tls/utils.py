from typing import List, Dict, Tuple, Optional
import socket

from pylstar.Letter import Letter
from pylstar.Word import Word
from pylstar.KnowledgeTree import KnowledgeTree

from scapy.layers.tls.record import TLSAlert, _tls_alert_description


class Endpoint:
    def __init__(self, endpoint_str: str):
        self._host, port_str = endpoint_str.split(":")
        self._port = int(port_str)

    def check(self) -> bool:
        try:
            socket.getaddrinfo(self._host, self._port)
            return True
        except socket.gaierror:
            return False

    def __str__(self):
        return f"{self._host}:{self._port}"

    def as_tuple(self):
        return self._host, self._port


class InvalidCryptoMaterialLine(BaseException):
    pass


class CryptoMaterial:
    def __init__(self):
        self.material: Dict[str, Tuple[str, str]] = {}
        self.default_cert: Optional[str] = None

    def add(self, arg_line):
        elts = arg_line.split(":")
        if len(elts) == 3:
            elts.append(False)
        elif len(elts) == 4 and elts[3] == "DEFAULT":
            elts[3] = True
        else:
            raise InvalidCryptoMaterialLine

        name, cert, key, default_cert = elts
        self.material[name] = (cert, key)
        if default_cert:
            self.default_cert = name

    def iter_names(self):
        for name in self.material:
            yield name

    def iter_non_default_names(self):
        for name in self.material:
            if name != self.default_cert:
                yield name

    def default_material(self) -> Tuple[Optional[str], Optional[str]]:
        if self.default_cert:
            return self.material[self.default_cert]
        return None, None

    def get_material(self, name: str) -> Tuple[str, str]:
        return self.material[name]

    def __nonzero__(self):
        return bool(self.material)


def abstract_alert_message(alert: TLSAlert):
    if alert.level == 1:
        alert_level = "Warning"
    elif alert.level == 2:
        alert_level = "FatalAlert"
    else:
        return "UnknownPacket"
    try:
        return f"{alert_level}({_tls_alert_description[alert.descr]})"
    except KeyError:
        return "UnknownPacket"


def abstract_response(response):
    msg_type = []
    for rsp in response:
        try:
            # If rsp.load exists, it means that scapy was not able to parse the packet correctly
            _ = rsp.load
            msg_type.append("UnknownPacket")
            continue
        except AttributeError:
            pass
        if isinstance(rsp, TLSAlert):
            msg_type.append(abstract_alert_message(rsp))
        else:
            abstract_msg = str(type(rsp)).rsplit(".", maxsplit=1)[-1].replace("'>", "")
            if abstract_msg == "Raw":
                abstract_msg = "UnknownPacket"
            elif abstract_msg == "TLSApplicationData":
                # If scapy interprets a packet as ApplicationData, check if the data makes sense
                try:
                    rsp.data.decode("utf-8")
                except UnicodeDecodeError:
                    abstract_msg = "UnknownPacket"
            msg_type.append(abstract_msg)
        if "UnknownPacket" in msg_type:
            return ["UnknownPacket"]

    return msg_type


def fill_answer_with(prefix: List[Letter], symbol: str, length: int) -> List[Letter]:
    letters = prefix
    while len(letters) < length:
        letters.append(Letter(symbol))
    return letters

def get_expected_output(
    input_word: Word, knowledge_tree: KnowledgeTree
) -> List[Letter]:
    prefix = input_word.letters[:-1]
    while prefix:
        try:
            prefix_word = Word(letters=prefix)
            output_prefix = knowledge_tree.get_output_word(prefix_word).letters
            expected_output_word = [letter.name.strip("'") for letter in output_prefix]
            if expected_output_word[-1] == "EOF":
                return fill_answer_with(output_prefix, "EOF", len(input_word.letters))
            return expected_output_word
        # pylint: disable=broad-except
        except Exception:
            prefix.pop()
    return []


def read_next_msg(tls_session, timeout=None):
    try:
        if timeout:
            tls_session.get_next_msg(socket_timeout=timeout)
        else:
            tls_session.get_next_msg()
    except socket.timeout:
        return []
    except ConnectionResetError:
        return None
    except BrokenPipeError:
        return None
    if not tls_session.buffer_in:
        return None
    result = abstract_response(tls_session.buffer_in)
    tls_session.buffer_in = []
    return result
