/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <glog/logging.h>

#include <fizz/crypto/Utils.h>
#include <folly/init/Init.h>
#include <folly/portability/GFlags.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/Types.h>

#include "Client.h"

DEFINE_string(host, "192.168.1.100", "Echo server hostname/IP");
DEFINE_int32(port, 6666, "Echo server port");
DEFINE_string(
    mode,
    "server",
    "Mode to run in: 'client', 'server', transport-server");
DEFINE_string(
    token,
    "",
    "Client new token string to attach to connection initiation");
DEFINE_bool(use_datagrams, false, "Use QUIC datagrams to communicate");
DEFINE_int64(
    active_conn_id_limit,
    10,
    "Maximum number of active connection IDs a peer supports");
DEFINE_bool(enable_migration, true, "Enable/disable migration");
DEFINE_bool(use_stream_groups, false, "Enable/disable stream groups");
DEFINE_bool(
    disable_rtx,
    false,
    "Enable/disable retransmission for stream groups");

using namespace quic::samples;
using namespace quic;

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::Init init(&argc, &argv);
  fizz::CryptoUtils::init();

    EchoClient client(
        FLAGS_host,
        FLAGS_port,
        FLAGS_use_datagrams,
        FLAGS_active_conn_id_limit,
        FLAGS_enable_migration,
        FLAGS_use_stream_groups);
    // std::cout << "TEST:" << FLAGS_token << std::endl; 
    client.start(FLAGS_token);
    // 创建一个 LongHeaderBuilder
    // auto builder = LongHeaderBuilder(LongHeader::Types::Initial);

    // // 使用 builder 创建一个 LongHeader 对象
    // ConnectionId srcConnId = "";  // 源连接ID
    // ConnectionId dstConnId = "";  // 目标连接ID
    // PacketNum packetNum = "";  // 包号
    // QuicVersion version = "";  // Quic版本
    // std::string token = "";  // 令牌
    // LongHeader header = builder(srcConnId, dstConnId, packetNum, version, token);
  return 0;
}
