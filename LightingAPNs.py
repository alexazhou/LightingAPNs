import json
import logging
import os
import socket
import select
import ssl
import struct
import sys
import time
import codecs


APNS_MODE_SANDBOX = 0
APNS_MODE_PRODUCTION = 1


APNS_ERRORS = {
    1:'Processing error',
    2:'Missing device token',
    3:'missing topic',
    4:'missing payload',
    5:'invalid token size',
    6:'invalid topic size',
    7:'invalid payload size',
    8:'invalid token',
    255:'Unknown'
}

class connecting_pool():
    def __init__(self, cert_path, mode, max_connection ):

        if not os.path.exists(cert_path):
            logging.error("Invalid certificate path: %s" % cert_path)
            raise Exception("Invalid certificate path")

        if mode == APNS_MODE_SANDBOX:
            self.host = 'gateway.sandbox.push.apple.com'
        else:
            self.host = 'gateway.push.apple.com'

        logging.debug("APNs domin: %s"%self.host)

        self.cert_path = cert_path
        self.max_connection = max_connection
        self.unused_con_pool = []#未被使用的TLS连接
        self.used_con_pool = []#已经在使用中的连接
    
    def create_connections(self, num ):

        for idx in range(num):

            try:
                logging.info("Creating A TLS connection")
                sock = ssl.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    certfile=self.cert_path
                )
                sock.connect((self.host, 2195))
                logging.info("TLS connect success")

            except Exception as e:
                logging.error("Failed to connect: %s" % e)
                raise Exception("connect to apns server failed:%s"%e)

            self.unused_con_pool.append(sock)

    def get_a_connection(self):
        
        if( len(self.unused_con_pool) == 0 ):
            self.create_connections(1)

        con = self.unused_con_pool.pop()
        self.used_con_pool.append( con )

        return con

    def release_a_connection(self, con):
        
        if con not in self.used_con_pool:
            raise Exception("")

        self.used_con_pool.remove(con)
        self.unused_con_pool.append(con)


#向指定的设备列表推送消息
#返回成功推送的数量
def push_core(sock, device_tokens, pay_load):

    sendIdx = 0
    for ident in range( 1, len(device_tokens)+1 ):
        expiry = time.time() + 36000
        token = codecs.decode( device_tokens[ident - 1] ,'hex_codec')
        
        payload_bytes = pay_load.encode("utf-8")

        items = [1, int(ident), int(expiry), 32, token, len(payload_bytes), payload_bytes]
        pkt = struct.pack('!BIIH32sH%ds'%len(pay_load), *items)
        
        logging.debug("push to device:%s"%device_tokens[ident - 1])

        try:
            sock.write( pkt )
            sendIdx = ident
            logging.debug("write socket ok")
        except socket.error as e:
            logging.error("Socket write error: %s", e)
            break

        #time.sleep(3)

    # If there was an error sending, we will get a response on socket
    rs,ws,es=select.select([sock],[],[],3)

    if sock in rs:
        logging.error("There was a error")
        response = sock.read(6)
        command, status, failed_ident = struct.unpack('!BBI',response[:6])
        sendIdx= failed_ident
        logging.error("APNS Error: %s @ident:%s\n", APNS_ERRORS.get(status), failed_ident)

    sock.close()

    return sendIdx


'''
deviceTokens: token string list
payload: json string
'''
def push( device_tokens, pay_load):
    global pool 

    sock = pool.get_a_connection()

    logging.info("start push to %d device"%len(device_tokens))
    push_numbers = push_core(sock, device_tokens, pay_load)
    logging.info("push_numbers:%d"%push_numbers)

    return push_numbers

def config(cert_path, mode = APNS_MODE_SANDBOX ,max_connection = 5):
    global pool

    pool = connecting_pool( cert_path, APNS_MODE_SANDBOX, max_connection )



