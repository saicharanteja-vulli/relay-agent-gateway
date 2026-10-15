import asyncio
from relay.app import app

def test_chunked_body_stops_before_reading_remainder():
    async def run():
        consumed=0;messages=[]
        async def receive():
            nonlocal consumed
            consumed+=1
            assert consumed<=3
            return {'type':'http.request','body':b'x'*60000,'more_body':consumed<3}
        async def send(message): messages.append(message)
        scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST','scheme':'http','path':'/api/login','raw_path':b'/api/login','query_string':b'','root_path':'','headers':[(b'host',b'localhost'),(b'x-relay-client',b'dashboard'),(b'content-type',b'application/json')],'client':('127.0.0.1',1234),'server':('localhost',80)}
        await app(scope,receive,send)
        assert messages[0]['status']==413
        assert consumed==2, 'Oversized request must stop at the first chunk exceeding the cap'
    asyncio.run(run())
