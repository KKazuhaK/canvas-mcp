"""Terminate TLS on 127.0.0.1:9443 and relay raw bytes to 127.0.0.1:8819 (local demo only).
import asyncio, ssl, sys

async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data); await w.drain()
    except Exception:
        pass
    finally:
        w.close()

async def handle(cr, cw):
    try:
        ur, uw = await asyncio.open_connection("127.0.0.1", 8819)
    except OSError:
        cw.close(); return
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))

async def main():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(sys.argv[1], sys.argv[2])
    server = await asyncio.start_server(handle, "127.0.0.1", 9443, ssl=ctx)
    async with server:
        await server.serve_forever()

asyncio.run(main())
