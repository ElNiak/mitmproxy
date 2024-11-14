import asyncio
import re
import socket
import logging
import sys
from typing import Iterable

logger = logging.getLogger(__name__)
loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
for logger_inter in loggers:
    logger_inter.setLevel(logging.DEBUG)


# 1. mitmdump -s mitm_proxy.py --mode reverse:udp://localhost:4433 --set flow_detail=4  --set dumper_default_contentview=hex --ssl-insecure -v
#  mitmdump -s mitm_proxy.py --mode reverse:udp://localhost:4433 --set flow_detail=4  --set dumper_default_contentview=hex --ssl-insecure -vvv
# mitmdump -s mitm_proxy.py --mode reverse:quic://localhost:4433 --set flow_detail=4  --set dumper_default_contentview=hex --ssl-insecure -vvv
# mitmdump -s mitm_proxy.py --mode reverse:tls://localhost:4433 --set flow_detail=4  --set dumper_default_contentview=hex --ssl-insecure -vvv
# mitmdump -s mitm_proxy.py --mode reverse:quic://localhost:4433  --mode reverse:udp://localhost --set flow_detail=3  --set dumper_default_contentview=hex --ssl-insecure
# Configuration for the Java connection
JAVA_HOST = 'localhost'
JAVA_PORT = 5000

def send_to_java(data):
    """Send intercepted data to the Java app and retrieve the modified response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((JAVA_HOST, JAVA_PORT))
        s.sendall(data.encode('utf-8'))  # Send decrypted data
        modified_data = s.recv(4096)  # Receive modified data
    return modified_data.decode('utf-8')

# mitm consider QUIC as TCP messages (https://github.com/mitmproxy/mitmproxy/discussions/6448)
def tcp_message(flow):
    logger.info("Intercepted QUIC message")
    logger.info(flow)
    logger.info(flow.messages[-1].content)
    logger.info(flow.__dict__)
    logger.info(flow.client_conn.state.__dict__)
    logger.info(flow.server_conn.state.__dict__)
    # decrypted_data = flow.request.content.decode('utf-8')
    # logger.info("Sending decrypted data to Java for modification")
    # modified_data = send_to_java(decrypted_data)
    # flow.request.content = modified_data.encode('utf-8')
    # logger.info("Modified data injected back into flow")
    
def modify(data: bytes) -> bytes | Iterable[bytes]:
    logger.info("Intercepted response - modifying data")
    logger.info(data)
    return data

def responseheaders(flow):
    flow.response.stream = modify


def process_flow(flow):
    logger.info("Intercepted flow")
    logger.info(flow)
    logger.info(flow.__dict__)
    logger.info(flow.client_conn.state.__dict__)
    logger.info(flow.server_conn.state.__dict__)
    # decrypted_data = flow.request.content.decode('utf-8')
    # logger.info("Sending decrypted data to Java for modification")
    # modified_data = send_to_java(decrypted_data)
    # flow.request.content = modified_data.encode('utf-8')
    # logger.info("Modified data injected back into flow")
    
def receive_data(data):
    logger.info("Received data from Java")
    logger.info(data)
    return data

def udp_message(flow):
    logger.info("Intercepted QUIC 2 message")
    logger.info(flow)
    logger.info(flow.messages[-1].content)
    logger.info(flow.__dict__)
    logger.info(flow.client_conn.state.__dict__)
    logger.info(flow.server_conn.state.__dict__)
    
def websocket_message(flow):
    logger.info("Intercepted QUIC 3 message")
    assert flow.websocket is not None  # make type checker happy
    # get the latest message
    message = flow.websocket.messages[-1]

    # was the message sent from the client or server?
    if message.from_client:
        logger.info(f"Client sent a message: {message.content!r}")
    else:
        logger.info(f"Server sent a message: {message.content!r}")

    # manipulate the message content
    message.content = re.sub(rb"^Hello", b"HAPPY", message.content)

    if b"FOOBAR" in message.content:
        # kill the message and not send it to the other endpoint
        message.drop()

# async def request(flow):
#     logging.info(f"handle request: {flow.request.host}{flow.request.path}")
#     await asyncio.sleep(5)
#     logging.info(f"start  request: {flow.request.host}{flow.request.path}")
        
def request(flow):
    req = flow.request;
    try:
        print("Request: -----------------");
        print(req._assemble());
        print("--------------------------");
    except Exception as ee:
        print(str(ee));

def response(flow):
    res = flow.response;
    try:
        print("Response: -----------------");
        print(res._assemble());

        if res.content:
            size = len(res.content);
            size  = min(size, 20);
            if res.content[0:size] != res.get_decoded_content()[0:size]:
                print("\n\n");
                print(res.get_decoded_content());
        print("--------------------------");
    except Exception as ee:
        print(str(ee));