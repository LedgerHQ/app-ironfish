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

#include "crypto.h"

#include "coin.h"
#include "crypto_helper.h"
#include "cx.h"
#include "cx_blake2b.h"
#include "keys_def.h"
#include "rslib.h"
#include "zxformat.h"
#include "zxmacros.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];
uint8_t change_address[32];

static zxerr_t computeKeys(keys_t *saplingKeys) {
    if (saplingKeys == NULL) {
        return zxerr_no_data;
    }

    // Compute ask, nsk
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_ASK, saplingKeys->ask, true));
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_NSK, saplingKeys->nsk, true));

    // Compute ak, nsk
    // This function will make a copy of the first param --> There shouldn't be problems to overwrite the union
    CHECK_PARSER_OK(generate_key(saplingKeys->ask, SpendingKeyGenerator, saplingKeys->ak));
    CHECK_PARSER_OK(generate_key(saplingKeys->nsk, ProofGenerationKeyGenerator, saplingKeys->nk));

    // Compute ivk and ovk
    CHECK_PARSER_OK(computeIVK(saplingKeys->ak, saplingKeys->nk, saplingKeys->ivk));
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_OVK, saplingKeys->ovk, false));

    // Compute public address
    CHECK_PARSER_OK(generate_key(saplingKeys->ivk, PublicKeyGenerator, saplingKeys->address));

    return zxerr_ok;
}

__Z_INLINE zxerr_t copyKeys(keys_t *saplingKeys, key_kind_e requestedKeys, uint8_t *output, uint16_t outputLen) {
    if (saplingKeys == NULL || output == NULL) {
        return zxerr_no_data;
    }

    switch (requestedKeys) {
        case PublicAddress:
            if (outputLen < KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->address, KEY_LENGTH);
            break;

        case ViewKeys:
            if (outputLen < 4 * KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->ak, KEY_LENGTH);
            memcpy(output + KEY_LENGTH, saplingKeys->nk, KEY_LENGTH);
            memcpy(output + 2 * KEY_LENGTH, saplingKeys->ivk, KEY_LENGTH);
            memcpy(output + 3 * KEY_LENGTH, saplingKeys->ovk, KEY_LENGTH);
            break;

        case ProofGenerationKey:
            if (outputLen < 2 * KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->ak, KEY_LENGTH);
            memcpy(output + KEY_LENGTH, saplingKeys->nsk, KEY_LENGTH);
            break;

        default:
            return zxerr_invalid_crypto_settings;
    }
    return zxerr_ok;
}

zxerr_t crypto_generateSaplingKeys(uint8_t *output, uint16_t outputLen, key_kind_e requestedKey) {
    if (output == NULL) {
        return zxerr_buffer_too_small;
    }

    zxerr_t error = zxerr_unknown;
    MEMZERO(output, outputLen);

    // Generate spending key
    uint8_t privateKeyData[SK_LEN_25519] = {0};
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_Ed25519, hdPath, HDPATH_LEN_DEFAULT,
                                                     privateKeyData, NULL, NULL, 0));

    keys_t saplingKeys = {0};
    memcpy(saplingKeys.spendingKey, privateKeyData, KEY_LENGTH);
    error = computeKeys(&saplingKeys);

    // Copy keys
    if (error == zxerr_ok) {
        error = copyKeys(&saplingKeys, requestedKey, output, outputLen);
    }

catch_cx_error:
    MEMZERO(privateKeyData, sizeof(privateKeyData));
    MEMZERO(&saplingKeys, sizeof(saplingKeys));

    return error;
}

zxerr_t crypto_sign(const uint8_t publickeyRandomness[32], const uint8_t txnHash[32], uint8_t *output, uint16_t outputLen) {
    if (output == NULL || outputLen < REDJUBJUB_SIGNATURE_LEN) {
        return zxerr_no_data;
    }
    MEMZERO(output, outputLen);
    zxerr_t error = zxerr_unknown;

    // Generate spending key
    uint8_t privateKeyData[SK_LEN_25519] = {0};
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_Ed25519, hdPath, HDPATH_LEN_DEFAULT,
                                                     privateKeyData, NULL, NULL, 0));

    keys_t saplingKeys = {0};
    memcpy(saplingKeys.spendingKey, privateKeyData, KEY_LENGTH);
    error = computeKeys(&saplingKeys);

    uint8_t randomnizedPrivateKey[KEY_LENGTH] = {0};
    randomizeKey(saplingKeys.ask, publickeyRandomness, randomnizedPrivateKey);

    if (error == zxerr_ok) {
        uint8_t rng[RNG_LEN] = {0};
        cx_rng_no_throw(rng, RNG_LEN);
        error = crypto_signRedjubjub(randomnizedPrivateKey, rng, txnHash, output);
    }

catch_cx_error:
    MEMZERO(privateKeyData, sizeof(privateKeyData));
    MEMZERO(&saplingKeys, sizeof(saplingKeys));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

zxerr_t crypto_fillKeys(uint8_t *buffer, uint16_t bufferLen, key_kind_e requestedKey, uint16_t *cmdResponseLen) {
    if (buffer == NULL || cmdResponseLen == NULL) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    CHECK_ZXERR(crypto_generateSaplingKeys(buffer, bufferLen, requestedKey));
    switch (requestedKey) {
        case PublicAddress:
            *cmdResponseLen = KEY_LENGTH;
            break;

        case ViewKeys:
            *cmdResponseLen = 4 * KEY_LENGTH;
            break;

        case ProofGenerationKey:
            *cmdResponseLen = 2 * KEY_LENGTH;
            break;

        default:
            return zxerr_out_of_bounds;
    }

    return zxerr_ok;
}

zxerr_t crypto_get_change_address(void) {
    MEMZERO(change_address, sizeof(change_address));
    CHECK_ZXERR(crypto_generateSaplingKeys(change_address, sizeof(change_address), PublicAddress));
    return zxerr_ok;
}
