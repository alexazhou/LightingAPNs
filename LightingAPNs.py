#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Date    : 2015-04-16 16:43:40
# @Author  : Alexa (AlexaZhou@163.com)
# @Link    : 
# @Disc    : 
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
    255:'Unknown',

    256:'SSL connection disconnected'
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
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 30)#keep sock alive
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

'''
push pay_load to many devices
sock: TLS sock to APNs
device_tokens: token string in list
pay_load: json string
return: pushed number, error
'''
def push_core(sock, device_tokens, pay_load):

    sendIdx = 0
    for ident in range(  len(device_tokens) ):
        expiry = time.time() + 36000
        token_str = device_tokens[ident]
        token = codecs.decode( token_str ,'hex_codec')
        
        payload_bytes = pay_load.encode("utf-8")

        items = [1, int(ident), int(expiry), 32, token, len(payload_bytes), payload_bytes]
        pkt = struct.pack('!BIIH32sH%ds'%len(pay_load), *items)
        
        logging.debug("push to device:%s"%token_str)

        try:
            sock.write( pkt )
            sendIdx = ident
        except socket.error as e:
            logging.error("Socket write error: %s on token %s"%(e,token_str))
            break

        #time.sleep(3)

    # If there was an error sending, we will get a response on socket
    rs,ws,es=select.select([sock],[],[],3)
    error = 0
    if sock in rs:
        logging.error("There was a error")
        response = sock.read(6)
        if len(response) == 0:
            logging.error("TLS Socket disconnected!!!")
            failed_ident = 256
        else:
            command, error, failed_ident = struct.unpack('!BBI',response[:6])
            sendIdx= failed_ident - 1
            logging.error("APNS Error: %s @ident:%s\n", APNS_ERRORS.get(error), failed_ident)

    return sendIdx + 1,error


'''
device_tokens: token string list
pay_load: json string
return: failed token list
'''
def push( device_tokens, pay_load ):
    global pool 

    failed_tokens = []
    push_numbers = 0

    logging.info("start push to %d device"%len(device_tokens))
    while len(device_tokens) != 0:
    
        sock = pool.get_a_connection()
        push_numbers,error = push_core(sock, device_tokens, pay_load )

        if error == 0:
            device_tokens = []
        else:
            if error == 8:#invalid token
                failed_tokens.append( device_tokens[push_numbers] )
                device_tokens = device_tokens[ push_numbers+1 :]
            else:
                failed_tokens.append( device_tokens[push_numbers:] )
                device_tokens = []

        sock.close()
            
    logging.info("pushed to %d device at all"%push_numbers)
    
    return failed_tokens

def config(cert_path, mode = APNS_MODE_SANDBOX ,max_connection = 5):
    global pool

    pool = connecting_pool( cert_path, mode, max_connection )



