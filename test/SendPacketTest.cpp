#include <folly/Expected.h>
#include <iostream>
#include <quic/QuicException.h>
#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicPacketScheduler.h>
#include <quic/api/QuicSocket.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/StateData.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/server/handshake/FizzServerHandshake.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include "SendPacketTest.h"

using namespace quic;
// using namespace quic::test;

class init_conn {
 public:

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    std::string ServeridString = "114514";
    std::vector<uint8_t> ServeridVector(ServeridString.begin(), ServeridString.end());
    quic::ConnectionId Serverid(ServeridVector);
    conn->serverConnectionId = Serverid;
    std::string ClientidString = "1919810";
    std::vector<uint8_t> ClientidVector(ClientidString.begin(), ClientidString.end());
    quic::ConnectionId Clientid(ClientidVector);
    conn->clientConnectionId = Clientid;
    conn->version = QuicVersion::QUIC_V1;
    conn->localAddress = folly::SocketAddress("192.168.0.10", 6666);
    conn->peerAddress = folly::SocketAddress("192.168.0.100", 6666);
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow * 1000;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow * 1000;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow * 1000;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow * 1000;
    conn->statsCallback = quicStats_.get();
    // conn->initialWriteCipher = createNoOpAead();
    // conn->initialHeaderCipher = createNoOpHeaderCipher();
    conn->streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn->streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    return conn;
  }

  QuicVersion getVersion(QuicClientConnectionState& conn) {
    return conn.version.value_or(*conn.originalVersion);
  }

  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  std::unique_ptr<MockQuicStats> quicStats_;
};

auto buildEmptyPacket(
    QuicClientConnectionState& conn,
    PacketNumberSpace pnSpace,
    bool shortHeader = false) {
  folly::Optional<PacketHeader> header;
  if (shortHeader) {
    header = ShortHeader(
        ProtectionType::KeyPhaseZero,
        *conn.clientConnectionId,
        conn.ackStates.appDataAckState.nextPacketNum);
  } else {
    if (pnSpace == PacketNumberSpace::Initial) {
      header = LongHeader(
          LongHeader::Types::Initial,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.initialAckState->nextPacketNum,
          *conn.version);
    } else if (pnSpace == PacketNumberSpace::Handshake) {
      header = LongHeader(
          LongHeader::Types::Handshake,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.handshakeAckState->nextPacketNum,
          *conn.version);
    } else if (pnSpace == PacketNumberSpace::AppData) {
      header = LongHeader(
          LongHeader::Types::ZeroRtt,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.appDataAckState.nextPacketNum,
          *conn.version);
    }
  }
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(*header),
      getAckState(conn, pnSpace).largestAckedByPeer.value_or(0));
  builder.encodePacketHeader();
  DCHECK(builder.canBuildPacket());
  return std::move(builder).buildPacket();
}

uint64_t getEncodedSize(const RegularQuicPacketBuilder::Packet& packet) {
  // calculate size as the plaintext size
  uint32_t encodedSize = 0;
  if (!packet.header.empty()) {
    encodedSize += packet.header.computeChainDataLength();
  }
  if (!packet.body.empty()) {
    encodedSize += packet.body.computeChainDataLength();
  }
  return encodedSize;
}

uint64_t getEncodedBodySize(const RegularQuicPacketBuilder::Packet& packet) {
  // calculate size as the plaintext size
  uint32_t encodedBodySize = 0;
  if (!packet.body.empty()) {
    encodedBodySize += packet.body.computeChainDataLength();
  }
  return encodedBodySize;
}


int main()
{
    // UpdateConnection();
    folly::EventBase evb;
    std::shared_ptr<FollyQuicEventBase> qEvb =
        std::make_shared<FollyQuicEventBase>(&evb);
    // FollyQuicAsyncUDPSocket sock(qEvb);
        // 设置连接ID和版本，仅示例值
    std::string srcConnIdStr = "114514";
    std::vector<uint8_t> srcConnIdData(srcConnIdStr.begin(), srcConnIdStr.end());
    quic::ConnectionId srcConnId(srcConnIdData);
    // std::cout << "src:" << srcConnId << std::endl;

    std::string dstConnIdStr = "1919810";
    std::vector<uint8_t> dstConnIdData(dstConnIdStr.begin(), dstConnIdStr.end());
    quic::ConnectionId dstConnId(dstConnIdData);
    // std::cout << "dst:" << dstConnId << std::endl;

    // 假设已经有以下变量
    // QuicNodeType nodeType = QuicNodeType::Client; // QUIC 节点类型
    // QuicConnectionStateBase connection(nodeType); // QUIC 连接状态
    // QuicConnectionStateBase &conn = connection;
    // conn.clientConnectionId = srcConnId;
    // conn.serverConnectionId = dstConnId;
    // conn.version = QuicVersion::QUIC_V1;
    // conn.localAddress = folly::SocketAddress("192.168.0.3", 6666);
    // conn.peerAddress = folly::SocketAddress("127.0.0.1", 6666);
    init_conn initializer;
    std::unique_ptr<QuicConnectionStateBase> connection = initializer.createConn();
    QuicConnectionStateBase &conn = *connection;
    std::unique_ptr<quic::QuicAsyncUDPSocket> _socket =
        std::make_unique<quic::FollyQuicAsyncUDPSocket>(qEvb);
    QuicAsyncUDPSocket &socket = *_socket; // QUIC 使用的 UDP 套接字
    // 使用 MockAead
    // std::unique_ptr<quic::Aead> aead = std::make_unique<MockAead>();
    FizzCryptoFactory factory;
    std::unique_ptr<Aead> _aead =  factory.makeInitialAead("CLHO",dstConnId, QuicVersion::QUIC_V1);
    Aead &aead = *_aead; // 数据包加密工具
    connection->initialWriteCipher = std::move(_aead);
    std::cout << aead.getCipherOverhead() << std::endl;
    std::unique_ptr<PacketNumberCipher> _headerCipher = factory.makePacketNumberCipher(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
    PacketNumberCipher &headerCipher = *_headerCipher; // 数据包编号加密工具
    connection->initialHeaderCipher = std::move(_headerCipher);
    std::cout << headerCipher.keyLength() << std::endl;
    QuicVersion version = QuicVersion::QUIC_V1;        // 使用的 QUIC 版本


    // // 构建长格式头的构建器
    // auto builder = LongHeaderBuilder(LongHeader::Types::Initial);

    // // 创建长格式头
    // auto packetNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
    // auto header = builder(srcConnId, dstConnId, packetNum, version, "");
    // // std::cout << header << std::endl;
    // std::cout <<  static_cast<int>(header.getHeaderForm()) << std::endl;
    // std::cout  << header.asLong() << std::endl;


    // 创建帧调度器（此处仅为示例，实际情况下应包含必要的握手帧）
    // FrameScheduler scheduler = FrameScheduler::Builder(conn, EncryptionLevel::Initial,
    // PacketNumberSpace::Initial, "HandshakeScheduler").build();
    auto LocalAdr = "192.168.0.10";
    uint16_t port = 6666;
    // conn.localAddress = folly::SocketAddress(LocalAdr);
    auto DstAdr = "192.168.0.100";
    // conn.peerAddress = folly::SocketAddress(DstAdr, port);
    socket.connect(folly::SocketAddress(DstAdr, port));
    // std::cout << socket.address() << std::endl;
    // 发送握手数据包
    uint64_t packetLimit = 1; // 仅发送一个握手包
    // std::cout << socket.bind();
    auto result = writeQuicDataToSocket(socket, conn, srcConnId, dstConnId, aead, headerCipher, version, packetLimit);

    std::cout << "发送的握手数据包数量: " << result.packetsWritten << std::endl;
}