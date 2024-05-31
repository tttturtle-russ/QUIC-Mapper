from stubs.cke_factory import (
    change_second_byte,
    shorten_padding,
    extend_padding_to_the_end,
    wrong_tls_version,
    longer_pms,
    shorter_pms,
)


ref_m = b"\x00\x02" + (b"A" * 100) + b"\x00" + b"\x03\x03" + (b"B" * 46)


def len_msg(m):
    i = m[1:].find(b"\x00")
    if i == -1:
        return 0
    return len(m) - i - 2


def extract_version(m):
    i = m[1:].find(b"\x00")
    if i == -1:
        return None
    return m[i + 2 : i + 4]


def test_ref_m():
    assert len_msg(ref_m) == 48
    assert extract_version(ref_m) == b"\x03\x03"


def test_change_second_byte():
    assert len_msg(change_second_byte(ref_m)) == 48
    assert extract_version(change_second_byte(ref_m)) == b"\x03\x03"


def test_shorten_padding():
    assert len_msg(shorten_padding(ref_m)) > 48


def test_extend_padding_to_the_end():
    assert len_msg(extend_padding_to_the_end(ref_m)) == 0
    assert extract_version(extend_padding_to_the_end(ref_m)) is None


def test_wrong_tls_version():
    assert len_msg(wrong_tls_version(ref_m)) == 48
    assert extract_version(wrong_tls_version(ref_m)) == b"\x02\x03"


def test_longer_pms():
    assert len_msg(longer_pms(ref_m)) == 49
    assert extract_version(longer_pms(ref_m)) == b"\x03\x03"


def test_shorter_pms():
    assert len_msg(shorter_pms(ref_m)) == 47
    assert extract_version(shorter_pms(ref_m)) == b"\x03\x03"
