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

group_id = 0

def get_group_id():
    global group_id
    group_id += 1
    if group_id > 0xff:
        group_id = 0

    return group_id

class ConnectToAPNsError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

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
    
    def create_connections(self, num ):

        for idx in range(num):

            try:
                logging.info("Creating A TLS connection")
                sock = ssl.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    certfile=self.cert_path
                )
                
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)#keep sock alive
                sock.settimeout( 15 )

                sock.connect((self.host, 2195))
                logging.info("TLS connect success")

            except Exception as e:
                logging.error("Failed to connect: %s" % e)
                raise ConnectToAPNsError("connect to apns server failed:%s"%e)

            self.unused_con_pool.append(sock)

    def check_a_connection(self, sock):

        rs,ws,es=select.select([sock],[],[],0)
        #print("rs:%s,ws:%s,es:%s"%(rs,ws,es))
        if sock in rs:
            return False
        else:
            return True

    def get_a_connection(self):
                
        while len(self.unused_con_pool) > 0:
            con = self.unused_con_pool.pop()
            if self.check_a_connection(con):
                return con

        self.create_connections(1)

        return self.unused_con_pool.pop() 

    def release_a_connection(self, con):
        
        if self.check_a_connection( con ):
            self.unused_con_pool.append( con )
        else:
            logging.debug("The connect to release is broken, so drop it")
        

'''
push pay_load to many devices
sock: TLS sock to APNs
device_tokens: token string in list
pay_load: json string
return: pushed number, error
'''
def push_core(sock, device_tokens, pay_load):

    baseIdx = get_group_id()<<24
    sendAmount = 0
    for ident in range(  len(device_tokens) ):
        expiry = time.time() + 36000
        token_str = device_tokens[ident]
        token = codecs.decode( token_str ,'hex_codec')
        
        payload_bytes = pay_load.encode("utf-8")

        items = [1, baseIdx + ident, int(expiry), 32, token, len(payload_bytes), payload_bytes]
        pkt = struct.pack('!BIIH32sH%ds'%len(pay_load), *items)
        
        logging.debug("push to device:%s"%token_str)

        try:
            sock.write( pkt )
            sendAmount = ident + 1
        except socket.error as e:
            logging.error("Socket write error: %s on token %s"%(e,token_str))
            break

        #time.sleep(3)

    # If there was an error sending, we will get a response on socket
    rs,ws,es=select.select([sock],[],[],3)
    error = 0
    if sock in rs:
        logging.error("There was a error")
        
        try:
            response = sock.read(6)
        except:#after connection disconnect, the read method may raise a "ConnectionResetError: [Errno 54] Connection reset by peer" Exception
            response = b""
        
        logging.error("TLS Socket disconnected!!!")

        if len(response) != 6:
            error = 256
        else:
            command, error, failed_ident = struct.unpack('!BBI',response[:6])
            logging.error("APNS Error: %s @Ident:%s\n"%(APNS_ERRORS.get(error), hex(failed_ident)))

            if failed_ident>>24 != baseIdx>>24:#Is a overdue error report
                sendAmount = 0
                logging.error("Is a overdue error report")
            else:

                if (failed_ident - baseIdx ) + 1 > sendAmount :
                    logging.error("Got a Invalid ident\n")
                else:
                    sendAmount= failed_ident - baseIdx
                    logging.error("Invalid Token:%s\n"%device_tokens[failed_ident - baseIdx])


    return { "send_number":sendAmount , "error":error }


'''
device_tokens: token string list
pay_load: json string
progress_callback: callback with the amount of token has been send
return: failed token list
'''
def push( device_tokens, pay_load ):
    global pool 

    failed_tokens = []
    invalid_tokens = []
    processed_amount = 0
    error = 0

    logging.info("start push to %d device"%len(device_tokens))
    while processed_amount < len(device_tokens):
    
        try:
            sock = pool.get_a_connection() #this method may raise a exception

            ret_info = push_core(sock, device_tokens[processed_amount:], pay_load )
            processed_amount += ret_info["send_number"]
            error = ret_info["error"]

            pool.release_a_connection(sock)

        except ConnectToAPNsError:
            error = 256
            logging.error("Connect to APNs failed")

        if error != 0:

            if error == 8:#invalid token
                failed_tokens.append( device_tokens[processed_amount] )
                invalid_tokens.append( device_tokens[processed_amount] )
                processed_amount += 1
            else:
                failed_tokens = failed_tokens + device_tokens[processed_amount:]
                processed_amount += len( device_tokens[processed_amount:] )

    logging.info("LightingAPNS: pushed to %d device at all"%(len(device_tokens) - len(failed_tokens)))
    
    return {"failed_tokens":failed_tokens,"invalid_tokens":invalid_tokens,"error":error}

def config(cert_path, mode = APNS_MODE_SANDBOX ,max_connection = 5):
    global pool

    pool = connecting_pool( cert_path, mode, max_connection )



