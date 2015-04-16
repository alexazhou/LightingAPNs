#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Date    : 2015-04-16 16:43:40
# @Author  : Alexa (AlexaZhou@163.com)
# @Link    : 
# @Disc    : 

import LightingAPNs as apns
import logging
import codecs
import json
import uuid

def main():
    logging.basicConfig(level = logging.NOTSET)

    apns.config("cert-key.pem")

    token = "******cacfd12b4a0a1609fcf16345a61f765763c67e052f374bc28afbcff8f4"

    pay_load =  json.dumps({
            'aps': {
                'alert': 'Push Test %d: %s' % (1, str(uuid.uuid4())[:8])
            }
        })

    deviceTockens = [token]
    ret = apns.push( deviceTockens, pay_load )

    logging.info("Pushed to %d device at all"%ret)


if __name__ == '__main__':
    main()

    input('Press any key to exit.')
else:
    print ('test.py had been imported as a module')

