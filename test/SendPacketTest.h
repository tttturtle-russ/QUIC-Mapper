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

class MockAead : public quic::Aead {
public:
    ~MockAead() override = default;

    folly::Optional<quic::TrafficKey> getKey() const override {
        // 返回一个空的 Optional，表示没有密钥
        return folly::none;
    }

    std::unique_ptr<folly::IOBuf> inplaceEncrypt(
        std::unique_ptr<folly::IOBuf>&& plaintext,
        const folly::IOBuf* /* associatedData */,
        uint64_t /* seqNum */) const override {
        // Correctly move the unique_ptr to the caller
        return std::move(plaintext);
    }


    folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
        std::unique_ptr<folly::IOBuf>&& ciphertext,
        const folly::IOBuf* /* associatedData */,
        uint64_t /* seqNum */) const override {
        // 模拟解密，直接返回原始数据
        return folly::make_optional(std::move(ciphertext));
    }

    size_t getCipherOverhead() const override {
        // 返回加密开销为 0
        return 0;
    }
};


