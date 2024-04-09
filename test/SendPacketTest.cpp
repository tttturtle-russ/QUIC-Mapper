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
#include "SendPacketTest.h"

using namespace quic;

int main(){

    folly::EventBase evb;
    std::shared_ptr<FollyQuicEventBase> qEvb =
    std::make_shared<FollyQuicEventBase>(&evb);
    // FollyQuicAsyncUDPSocket sock(qEvb);

    // 假设已经有以下变量
    QuicNodeType nodeType = QuicNodeType::Client;  // QUIC 节点类型
    QuicConnectionStateBase connection(nodeType);  // QUIC 连接状态
    QuicConnectionStateBase& conn = connection;
    std::unique_ptr<quic::QuicAsyncUDPSocket> _socket = 
    std::make_unique<quic::FollyQuicAsyncUDPSocket>(qEvb    );
    QuicAsyncUDPSocket& socket = *_socket;  // QUIC 使用的 UDP 套接字
    // 使用 MockAead
    // std::unique_ptr<quic::Aead> aead = std::make_unique<MockAead>();
    std::unique_ptr<Aead> _aead;
    Aead& aead = *_aead;  // 数据包加密工具

    std::unique_ptr<PacketNumberCipher> _headerCipher;
    PacketNumberCipher& headerCipher = *_headerCipher;  // 数据包编号加密工具
    QuicVersion version = QuicVersion::QUIC_V1;  // 使用的 QUIC 版本

    // 设置连接ID和版本，仅示例值
    std::string srcConnIdStr = "114514";
    std::vector<uint8_t> srcConnIdData(srcConnIdStr.begin(), srcConnIdStr.end());
    quic::ConnectionId srcConnId(srcConnIdData);

    std::string dstConnIdStr = "1919810";
    std::vector<uint8_t> dstConnIdData(dstConnIdStr.begin(), dstConnIdStr.end());
    quic::ConnectionId dstConnId(dstConnIdData);


    // 构建长格式头的构建器
    auto builder = LongHeaderBuilder(LongHeader::Types::Initial);

    // 创建长格式头
    auto packetNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
    auto header = builder(srcConnId, dstConnId, packetNum, version, "");

    // 创建帧调度器（此处仅为示例，实际情况下应包含必要的握手帧）
    FrameScheduler scheduler = FrameScheduler::Builder(conn, EncryptionLevel::Initial, PacketNumberSpace::Initial, "HandshakeScheduler").build();

    // 发送握手数据包
    uint64_t packetLimit = 1;  // 仅发送一个握手包
    auto result = writeQuicDataToSocket(socket, conn, srcConnId, dstConnId, aead, headerCipher, version, packetLimit);

    std::cout << "发送的握手数据包数量: " << result.packetsWritten << std::endl;
}