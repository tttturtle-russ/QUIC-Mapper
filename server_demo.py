import asyncio
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
import contextlib

import os
SERVER_CACERTFILE = os.path.join(os.path.dirname(__file__), "pycacert.pem")
SERVER_CERTFILE = os.path.join(os.path.dirname(__file__), "ssl_cert.pem")
SERVER_CERTFILE_WITH_CHAIN = os.path.join(
    os.path.dirname(__file__), "ssl_cert_with_chain.pem"
)
SERVER_KEYFILE = os.path.join(os.path.dirname(__file__), "ssl_key.pem")
SERVER_COMBINEDFILE = os.path.join(os.path.dirname(__file__), "ssl_combined.pem")
SKIP_TESTS = frozenset(os.environ.get("AIOQUIC_SKIP_TESTS", "").split(","))

def handle_stream(reader, writer):
    async def serve():
        data = await reader.read()
        writer.write(bytes(reversed(data)))
        writer.write_eof()

    asyncio.ensure_future(serve())

@contextlib.asynccontextmanager
async def run_server(configuration=None, host="::", **kwargs):
    if configuration is None:
        configuration = QuicConfiguration(is_client=False)
        configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = await serve(
        host=host,
        port=0,
        configuration=configuration,
        stream_handler=handle_stream,
        **kwargs,
    )
    try:
        yield server._transport.get_extra_info("sockname")[1]
    finally:
        server.close()

async def main():
    async with run_server() as port:
        print(f"Server is running on port {port}")
        # 这里可以插入你的代码，例如等待用户输入或者处理其他事件
        await asyncio.sleep(3600)  # 例如，让服务器运行一小时

# 运行主函数
asyncio.run(main())
