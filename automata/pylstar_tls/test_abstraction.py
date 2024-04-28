from scapy.layers.tls.record import TLSAlert
from utils import abstract_alert_message, abstract_response


def test_abstract_alert_message():
    assert abstract_alert_message(TLSAlert(level=1, descr=0)) == "Warning(close_notify)"
    assert (
        abstract_alert_message(TLSAlert(level=2, descr=40))
        == "FatalAlert(handshake_failure)"
    )
    assert abstract_alert_message(TLSAlert(level=0, descr=0)) == "UnknownPacket"
    assert abstract_alert_message(TLSAlert(level=1, descr=156)) == "UnknownPacket"


def test_abstract_response():
    assert abstract_response([TLSAlert(level=1, descr=0)]) == ["Warning(close_notify)"]
