import asyncio

# import pylstar.LSTAR
# from pylstar.Letter import Letter

from protocol import QUICClientProtocol


class QUICClientInferTool:
    def __init__(self, configuration, dst_addr, local_addr, local_port, handle):
        self.handle = handle
        self.configuration = configuration
        self.logger = configuration.quic_logger
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.transport = None
        self.protocol = QUICClientProtocol(dst_addr, local_addr, handle, local_port=local_port)
        self.local_endpoint = local_addr

    def concretize_client_messages(self, symbol):
        func_map = {
            "ConnectInitial": self.protocol.connect,
            # "InitialAck":self.protocol.initial_ack_packet(),
            "HandshakeInitial": self.protocol.initial_ack_packet,
            "Handshake": self.protocol.handshake_packet,
            "PathChallenge": self.protocol.path_challenge,
            "PathMigra": self.protocol.path_migrate,
            "PathResponse": self.protocol.path_response,
            "InitialClose": self.protocol.initial_close,
            "HandshakeClose": self.protocol.handshake_close,
            "OneRTTClose": self.protocol.onertt_close,
            "NewConnectionID": self.protocol.new_connection_id,
        }
        # for symbol in symbols:
            # if isinstance(symbol, Letter):
            #     print(symbol)
            #     for symbol in symbol.symbols:
            #         func = func_map.get(symbol, None)
            #         if func is None:
            #             raise ValueError(f"Unknown vocabulary :: {symbol}")
            #         func()
            # elif isinstance(symbol, str):
        print(symbol)
        func = func_map.get(symbol, None)
        if func is None:
            raise ValueError(f"Unknown vocabulary :: {symbol}")
        func()

    def reset(self):
        self.protocol.reset()

    def close(self):
        self.protocol.close_sock()
