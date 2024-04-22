from aioquic.quic.packet import *
from initial_packet import InitialPacket

p = InitialPacket()
p.new_packet()
p.push_frame(QuicFrameType.CRYPTO, {"bytes": b"hello"})
p.new_packet()
p.push_frame(QuicFrameType.CRYPTO, {"bytes": b"world"})
datagrams, packets = p.build()
print(datagrams)
print(packets)
# # 创建一个CryptoPair实例
# # 在实际使用中，你应该使用你自己的密钥和算法来初始化这个实例
# def create_crypto():
#     crypto = CryptoPair()
#     crypto.setup_initial(
#         bytes(8), is_client=True, version=QuicProtocolVersion.VERSION_1
#     )
#     return crypto
#
#
# # 创建一个QuicPacketBuilder实例
# def create_builder(host_cid=bytes(8), is_client=False, peer_cid=bytes(8), version=QuicProtocolVersion.VERSION_1):
#     return QuicPacketBuilder(
#         host_cid=host_cid,
#         is_client=is_client,
#         max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
#         packet_number=0,
#         peer_cid=peer_cid,
#         peer_token=b"",
#         spin_bit=False,
#         version=version,
#     )
#
#
# class SimpleClientProtocol(asyncio.DatagramProtocol):
#     def __init__(self, message, addr):
#         self.message = message
#         self.addr = addr
#
#     def connection_made(self, transport):
#         transport.sendto(self.message, self.addr)
#         # print('Data sent: {!r}'.format(self.message))
#
#
# def send_datagrams(datagrams, addr):
#     loop = asyncio.get_event_loop()
#     for datagram in datagrams:
#         connect = loop.create_datagram_endpoint(
#             lambda: SimpleClientProtocol(datagram, addr),
#             remote_addr=addr)
#         transport, protocol = loop.run_until_complete(connect)
#     transport.close()
#     loop.close()
#
#
# builder = create_builder(host_cid=b"11451400", is_client=True, peer_cid=b"19198100",
#                          version=QuicProtocolVersion.NEGOTIATION)
# crypto = create_crypto()
# # 开始一个新的packet
# builder.start_packet(packet_type=PACKET_TYPE_INITIAL, crypto=crypto)
#
# # 添加一个frame到当前的packet中
# frame_type = QuicFrameType.CRYPTO  # 这是一个示例，你应该使用你需要的frame类型
# try:
#     buffer = builder.start_frame(frame_type=frame_type, capacity=1)
#     # 在这里你可以写入你需要的数据到buffer中
#     buffer.push_bytes(b"CLHO")
#     buffer.push_bytes(bytes(builder.remaining_flight_space))
# except QuicPacketBuilderStop:
#     # 如果剩余的空间不足以容纳新的frame，则会抛出这个异常
#     pass
#
# # 结束当前的packet并获取构建好的datagrams和packets
# datagrams, packets = builder.flush()
#
# # message = "Hello World!".encode()
# addr = ('192.168.0.100', 9999)
# send_datagrams(datagrams, addr)
#
# addrs = '192.168.0.100'
# # 打印datagrams和packets以查看结果
# print(type(datagrams))
# quicConfig = QuicConfiguration()
# quicConnection = QuicConnection(configuration=quicConfig)
# for datagram in datagrams:
#     quicConnection.receive_datagram(datagram, ("192.168.0.100", 9999), now=0)
#     print("jiexizhong")
# ''' TODO 完成数据包的解析函数
#     try override the function _payload_received in QuicConnection (which used to deal with the received frame)
#     try to override the function received_datagram in QuicConnection (which used to deal with the received datagram)
# '''
#
#
# def get_packet_type(data: bytes, connection_id_length: Optional[int] = None) -> Optional[int]:
#     """
#     Parse a received datagram and return the packet type.
#
#     :param data: The datagram which was received.
#     :param connection_id_length: The length of the connection ID.
#     :return: The packet type, or None if the header cannot be parsed.
#     """
#     buf = Buffer(data=data)
#     try:
#         header = pull_quic_header(buf, host_cid_length=connection_id_length)
#         print("header.packet_type", header.packet_type)
#         print("header.version", header.version)
#         print("destination_cid", header.destination_cid)
#         print("source_cid", header.source_cid)
#         return header.packet_type
#
#     except ValueError:
#         return None
#
#
# print(get_packet_type(datagrams[0], ))
# print(PACKET_TYPE_INITIAL)
