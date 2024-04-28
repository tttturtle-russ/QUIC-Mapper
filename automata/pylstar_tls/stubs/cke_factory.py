from random import randrange
import codecs


def int_of_bytes(x_str):
    x_hex = codecs.encode(x_str, "hex")
    return int(x_hex, 16)


def bytes_of_int(x_int, byte_len):
    result = f"{x_int:x}"
    result = "0" * (byte_len * 2 - len(result)) + result
    return codecs.decode(result, "hex")


def change_byte(pos, val, msg):
    result = bytearray(msg)
    result[pos] = val
    return bytes(result)


def change_second_byte(msg):
    return change_byte(1, 2 ^ randrange(1, 256), msg)


def shorten_padding(msg):
    return change_byte(randrange(2, 10), 0, msg)


def extend_padding_to_the_end(msg):
    return msg[:2] + msg[2:].replace(b"\x00", b"\x01")


def wrong_tls_version(msg):
    return msg[:-48] + b"\x02" + msg[-47:]


def longer_pms(msg):
    return msg[:-50] + msg[-49:] + b"\xff"


def shorter_pms(msg):
    return msg[:-49] + b"\xff" + msg[-49:-1]


class CKEFactory:
    def __init__(self, pubkey_holder, tls_version):
        self.tls_version = tls_version
        self.key_length = (pubkey_holder.key_size + 7) // 8
        self.n = pubkey_holder.public_numbers().n
        self.e = pubkey_holder.public_numbers().e

    def _apply_f_and_encrypt(self, f, formated_plaintext):
        altered_plaintext = f(formated_plaintext)
        altered_plaintext_int = int_of_bytes(altered_plaintext)
        altered_ciphertext_int = pow(altered_plaintext_int, self.e, self.n)
        altered_ciphertext = bytes_of_int(altered_ciphertext_int, self.key_length)
        return altered_ciphertext

    def produce_altered_message(self, f):
        if self.key_length < 48 + 11:
            raise Exception("Cleartext challenge too long.")
        formated_plaintext = bytearray()
        formated_plaintext.append(0)
        formated_plaintext.append(2)
        for _i in range(self.key_length - 48 - 3):
            formated_plaintext.append(randrange(1, 256))
        formated_plaintext.append(0)

        formated_plaintext.append(self.tls_version >> 8)
        formated_plaintext.append(self.tls_version & 0xFF)
        for _i in range(48 - 2):
            formated_plaintext.append(randrange(0, 256))
        return self._apply_f_and_encrypt(f, bytes(formated_plaintext))

    def produce_valid_cke(self):
        return self.produce_altered_message(lambda x: x)

    def produce_cke_with_0002_modified(self):
        return self.produce_altered_message(change_second_byte)

    def produce_cke_with_small_padding(self):
        return self.produce_altered_message(shorten_padding)

    def produce_cke_with_no_msg(self):
        return self.produce_altered_message(extend_padding_to_the_end)

    def produce_cke_with_wrong_tls_version(self):
        return self.produce_altered_message(wrong_tls_version)

    def produce_cke_with_longer_pms(self):
        return self.produce_altered_message(longer_pms)

    def produce_cke_with_shorter_pms(self):
        return self.produce_altered_message(shorter_pms)
