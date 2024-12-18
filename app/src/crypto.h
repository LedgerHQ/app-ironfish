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

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>

#include "coin.h"
#include "zxerror.h"

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];
extern uint8_t change_address[32];

zxerr_t crypto_fillKeys(uint8_t *buffer, uint16_t bufferLen, key_kind_e requestedKey, uint16_t *cmdResponseLen);
zxerr_t crypto_sign(const uint8_t publickeyRandomness[32], const uint8_t txnHash[32], uint8_t *output, uint16_t outputLen);
zxerr_t crypto_get_change_address(void);
#if defined(LEDGER_SPECIFIC)
zxerr_t crypto_generateSaplingKeys(uint8_t *output, uint16_t outputLen, key_kind_e requestedKey);
#endif
#ifdef __cplusplus
}
#endif
