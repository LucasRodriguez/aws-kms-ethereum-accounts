#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os

from lambda_helper import (assemble_tx,
                           get_key,
                           get_tx_params,
                           calc_eth_address,
                           get_kms_public_key)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))
    operation = event.get('operation')

    # {"operation": "status"}
    if operation == 'status':
        key_id = event.get('key_id')

        pub_key = get_kms_public_key(key_id)
        eth_checksum_address = calc_eth_address(pub_key)

        return {'eth_checksum_address': eth_checksum_address}


    # {"operation": "send",
    #  "amount": 123,
    #  "dst_address": "0x...",
    #  "nonce": 0}
    elif operation == 'sign':
        if not (event.get('dst_address') and event.get('amount', -1) >= 0 and event.get('nonce', -1) >= 0):
            return {'operation': 'sign',
                    'error': 'missing parameter - sign requires amount, dst_address and nonce to be specified'}

        # get key_id from envent
        key_id = event.get('key_id')

        # get destination address from send request
        dst_address = event.get('dst_address')

        # get amount from send request
        amount = event.get('amount')

        # nonce from send request
        nonce = event.get('nonce')

        # data from send request
        data = event.get('data')

        # optional params
        chainid = event.get('chainid')
        type = event.get('type')
        max_fee_per_gas = event.get('max_fee_per_gas')
        max_priority_fee_per_gas = event.get('max_priority_fee_per_gas')

        # download public key from KMS
        pub_key = get_kms_public_key(key_id)

        # calculate the Ethereum public address from public key
        eth_checksum_addr = calc_eth_address(pub_key)

        # collect rawd parameters for Ethereum transaction
        tx_params = get_tx_params(dst_address=dst_address,
                                  amount=amount,
                                  data=data,
                                  nonce=nonce,
                                  chainid=chainid,
                                  type=type,
                                  max_fee_per_gas=max_fee_per_gas,
                                  max_priority_fee_per_gas=max_priority_fee_per_gas)

        # assemble Ethereum transaction and sign it offline
        raw_tx_signed_hash, raw_tx_signed_payload = assemble_tx(tx_params=tx_params,
                                                                params=key_id,
                                                                eth_checksum_addr=eth_checksum_addr,
                                                                chainid=chainid)

        return {"signed_tx_hash": raw_tx_signed_hash,
                "signed_tx_payload": raw_tx_signed_payload}

    elif operation == 'assign':

        key_id = get_key()

        pub_key = get_kms_public_key(key_id)

        # calculate the Ethereum public address from public key
        eth_checksum_address = calc_eth_address(pub_key)

        return {'eth_checksum_address': eth_checksum_address,
                'key_id': key_id}
