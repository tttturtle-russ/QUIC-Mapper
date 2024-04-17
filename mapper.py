from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import asyncio
from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE
from aioquic.buffer import Buffer
from aioquic.tls import Epoch
from aioquic.quic.packet import (
    NON_ACK_ELICITING_FRAME_TYPES,
    NON_IN_FLIGHT_FRAME_TYPES,
    PACKET_NUMBER_MAX_SIZE,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_MASK,
    QuicFrameType,
    is_long_header,
    QuicProtocolVersion,
)
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.logger import QuicLoggerTrace
from aioquic.quic.packet_builder import QuicPacketBuilder, QuicPacketBuilderStop
from aioquic.asyncio.protocol import *
# 创建一个CryptoPair实例
# 在实际使用中，你应该使用你自己的密钥和算法来初始化这个实例
def create_crypto():
    crypto = CryptoPair()
    crypto.setup_initial(
        bytes(8), is_client=True, version=QuicProtocolVersion.VERSION_1
    )
    return crypto

# 创建一个QuicPacketBuilder实例
def create_builder(host_cid=bytes(8),is_client=False,peer_cid=bytes(8)):
    return QuicPacketBuilder(
        host_cid=host_cid,
        is_client=is_client,
        max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
        packet_number=0,
        peer_cid=peer_cid,
        peer_token=b"",
        spin_bit=False,
        version=QuicProtocolVersion.VERSION_1,
    )

class SimpleClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, message, addr):
        self.message = message
        self.addr = addr

    def connection_made(self, transport):
        transport.sendto(self.message, self.addr)
        # print('Data sent: {!r}'.format(self.message))

def send_datagrams(datagrams, addr):
    loop = asyncio.get_event_loop()
    for datagram in datagrams:
        connect = loop.create_datagram_endpoint(
            lambda: SimpleClientProtocol(datagram, addr),
            remote_addr=addr)
        transport, protocol = loop.run_until_complete(connect)
    transport.close()
    loop.close()

builder = create_builder(host_cid=b"11451400",is_client=True,peer_cid=b"19198100")
crypto = create_crypto()
# 开始一个新的packet
builder.start_packet(packet_type=PACKET_TYPE_INITIAL, crypto=crypto)

# 添加一个frame到当前的packet中
frame_type = QuicFrameType.CRYPTO  # 这是一个示例，你应该使用你需要的frame类型
try:
    buffer = builder.start_frame(frame_type=frame_type, capacity=1)
    # 在这里你可以写入你需要的数据到buffer中
    buffer.push_bytes(b"CLHO")
    buffer.push_bytes(bytes(builder.remaining_flight_space))
except QuicPacketBuilderStop:
    # 如果剩余的空间不足以容纳新的frame，则会抛出这个异常
    pass

# 结束当前的packet并获取构建好的datagrams和packets
datagrams, packets = builder.flush()



loop = asyncio.get_event_loop()
# message = "Hello World!".encode()
addr = ('192.168.0.100', 9999)
for datagram in datagrams:
    connect = loop.create_datagram_endpoint(
        lambda: SimpleClientProtocol(datagram, addr),
        remote_addr=addr)
    transport, protocol = loop.run_until_complete(connect)
transport.close()
loop.close()


# 打印datagrams和packets以查看结果
print(type(datagrams))
