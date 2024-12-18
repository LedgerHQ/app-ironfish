/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#pragma once

#include <os_io_seproxyhal.h>
#include <stdint.h>

#include "apdu_codes.h"
#include "coin.h"
#include "crypto.h"
#include "tx.h"
#include "zxerror.h"

extern uint16_t cmdResponseLen;

__Z_INLINE zxerr_t app_fill_keys(key_kind_e requestedKey) {
    // Put data directly in the apdu buffer
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    cmdResponseLen = 0;
    const zxerr_t err = crypto_fillKeys(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE, requestedKey, &cmdResponseLen);

    if (err != zxerr_ok || cmdResponseLen == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return zxerr_ok;
}

__Z_INLINE void app_sign() {
    uint8_t txnHash[HASH_LEN] = {0};
    tx_getTxnHash(txnHash);
    uint8_t publickeyRandomness[KEY_LENGTH] = {0};
    tx_getPublicKeyRandomness(publickeyRandomness);
    const zxerr_t err = crypto_sign(publickeyRandomness, txnHash, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3);

    if (err != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, REDJUBJUB_SIGNATURE_LEN, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, REDJUBJUB_SIGNATURE_LEN + 2);
    }
}

__Z_INLINE void app_reject() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_cmd() {
    set_code(G_io_apdu_buffer, cmdResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, cmdResponseLen + 2);
}

__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE zxerr_t app_get_address() {
    zxerr_t err = crypto_get_change_address();

    if (err != zxerr_ok) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return zxerr_ok;
}
