/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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
#include "crypto_helper.h"

#include <string.h>

#include "coin.h"
#include "keys_personalizations.h"
#include "parser_common.h"
#include "rslib.h"
#include "zxformat.h"

#if defined(LEDGER_SPECIFIC)
#include "cx.h"
#include "cx_blake2b.h"
#endif
#include "blake2.h"

parser_error_t convertKey(const uint8_t spendingKey[KEY_LENGTH], const uint8_t modifier, uint8_t outputKey[KEY_LENGTH],
                          bool reduceWideByte) {
    uint8_t output[64] = {0};
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)EXPANDED_SPEND_BLAKE2_KEY,
                                           sizeof(EXPANDED_SPEND_BLAKE2_KEY)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, spendingKey, KEY_LENGTH));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, &modifier, 1));
    ASSERT_CX_OK(cx_blake2b_final(&ctx, output));
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t *)EXPANDED_SPEND_BLAKE2_KEY,
                                      sizeof(EXPANDED_SPEND_BLAKE2_KEY));
    blake2b_update(&state, spendingKey, KEY_LENGTH);
    blake2b_update(&state, &modifier, 1);
    blake2b_final(&state, output, sizeof(output));
#endif

    if (reduceWideByte) {
        CHECK_ERROR(from_bytes_wide(output, outputKey));
    } else {
        memcpy(outputKey, output, KEY_LENGTH);
    }
    return parser_ok;
}

parser_error_t generate_key(const uint8_t expandedKey[KEY_LENGTH], constant_key_t keyType, uint8_t output[KEY_LENGTH]) {
    if (keyType >= PointInvalidKey) {
        return parser_value_out_of_range;
    }
    CHECK_ERROR(scalar_multiplication(expandedKey, keyType, output));
    return parser_ok;
}

parser_error_t computeIVK(const ak_t ak, const nk_t nk, ivk_t ivk) {
    blake2s_state state = {0};
    blake2s_init_with_personalization(&state, 32, (const uint8_t *)CRH_IVK_PERSONALIZATION, sizeof(CRH_IVK_PERSONALIZATION));
    blake2s_update(&state, ak, KEY_LENGTH);
    blake2s_update(&state, nk, KEY_LENGTH);
    blake2s_final(&state, ivk, KEY_LENGTH);

    ivk[31] &= 0x07;
    return parser_ok;
}

parser_error_t transaction_signature_hash(parser_tx_t *txObj, uint8_t output[HASH_LEN]) {
    if (txObj == NULL) {
        return parser_no_data;
    }

    uint8_t personalization[8] = "IFsighsh";

    // Common transaction fields
    const uint8_t TXN_SIGNATURE_VERSION = 0;
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, personalization, sizeof(personalization)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, &TXN_SIGNATURE_VERSION, 1));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, &txObj->transactionVersion, 1));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, (const uint8_t *)&txObj->expiration, 4));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, (const uint8_t *)&txObj->fee, 8));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, txObj->randomizedPublicKey.ptr, txObj->randomizedPublicKey.len));
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, 32, (const uint8_t *)personalization, sizeof(personalization));
    blake2b_update(&state, &TXN_SIGNATURE_VERSION, 1);
    blake2b_update(&state, &txObj->transactionVersion, 1);
    blake2b_update(&state, &txObj->expiration, 4);
    blake2b_update(&state, &txObj->fee, 8);
    blake2b_update(&state, txObj->randomizedPublicKey.ptr, txObj->randomizedPublicKey.len);
#endif

    // Spends
    const uint16_t SPENDLEN = 32 + 192 + 32 + 32 + 4 + 32 + 64;
    for (uint64_t i = 0; i < txObj->spends.elements; i++) {
        const uint8_t *spend_i = txObj->spends.data.ptr + (SPENDLEN * i) + 32;
        // Don't hash neither public_key_randomness(32) nor binding_signature(64)
#if defined(LEDGER_SPECIFIC)
        ASSERT_CX_OK(cx_blake2b_update(&ctx, spend_i, SPENDLEN - (32 + 64)));
#else
        blake2b_update(&state, spend_i, SPENDLEN - (32 + 64));
#endif
    }

    // Outputs
    const uint16_t OUTPUTLEN = 192 + 328;
    for (uint64_t i = 0; i < txObj->outputs.elements; i++) {
        const uint8_t *output_i = txObj->outputs.data.ptr + (OUTPUTLEN * i);
#if defined(LEDGER_SPECIFIC)
        ASSERT_CX_OK(cx_blake2b_update(&ctx, output_i, OUTPUTLEN));
#else
        blake2b_update(&state, output_i, OUTPUTLEN);
#endif
    }

    // Mints
    const uint16_t MINTLEN = 32 + 192 + 193 + 8;
    uint16_t tmpOffset = 0;
    for (uint64_t i = 0; i < txObj->mints.elements; i++) {
        const uint8_t *mint_i = txObj->mints.data.ptr + tmpOffset;
        const int8_t transferOwnershipToLen = txObj->transactionVersion == V1 ? (-32) : mint_i[MINTLEN] == 1 ? 33 : 1;
        const uint16_t tmpMintLen = MINTLEN + transferOwnershipToLen + 64;

// Don't hash neither public_key_randomness(32) nor binding_signature(64)
#if defined(LEDGER_SPECIFIC)
        ASSERT_CX_OK(cx_blake2b_update(&ctx, mint_i + 32, tmpMintLen - (32 + 64)));
#else
        blake2b_update(&state, mint_i + 32, tmpMintLen - (32 + 64));
#endif

        tmpOffset += tmpMintLen;
    }

    // Burns
    const uint16_t BURNLEN = 32 + 8;
    for (uint64_t i = 0; i < txObj->burns.elements; i++) {
        const uint8_t *burn_i = txObj->burns.data.ptr + (BURNLEN * i);
#if defined(LEDGER_SPECIFIC)
        ASSERT_CX_OK(cx_blake2b_update(&ctx, burn_i, BURNLEN));
#else
        blake2b_update(&state, burn_i, BURNLEN);
#endif
    }

#if defined(LEDGER_SPECIFIC)
    ASSERT_CX_OK(cx_blake2b_final(&ctx, output));
#else
    blake2b_final(&state, output, HASH_LEN);
#endif
    return parser_ok;
}

// h_star function requires a and b elements. However, we receive b split in two elements to save some memory
// a = random[80] | r_bar[32] depending on who is calling this function
// b = [randomizedPublicKey | transactionHash]
static parser_error_t h_star(bytes_t a, const uint8_t randomizedPublicKey[32], const uint8_t transactionHash[32],
                             uint8_t output[32]) {
    uint8_t hash[BLAKE2B_OUTPUT_LEN] = {0};
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)SIGNING_REDJUBJUB,
                                           sizeof(SIGNING_REDJUBJUB)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, a.ptr, a.len));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, randomizedPublicKey, 32));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, transactionHash, 32));
    ASSERT_CX_OK(cx_blake2b_final(&ctx, hash));
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t *)SIGNING_REDJUBJUB,
                                      sizeof(SIGNING_REDJUBJUB));
    blake2b_update(&state, a.ptr, a.len);
    blake2b_update(&state, randomizedPublicKey, 32);
    blake2b_update(&state, transactionHash, 32);
    blake2b_final(&state, hash, BLAKE2B_OUTPUT_LEN);
#endif

    CHECK_ERROR(from_bytes_wide(hash, output));

    return parser_ok;
}

zxerr_t crypto_signRedjubjub(const uint8_t randomizedPrivateKey[KEY_LENGTH], const uint8_t rng[RNG_LEN],
                             const uint8_t transactionHash[HASH_LEN], uint8_t output[REDJUBJUB_SIGNATURE_LEN]) {
    uint8_t randomizedPublicKey[KEY_LENGTH] = {0};
    CHECK_PARSER_OK(scalar_multiplication(randomizedPrivateKey, SpendingKeyGenerator, randomizedPublicKey));

    // Signature [rbar, sbar]
    uint8_t *rbar = output;
    uint8_t *sbar = output + 32;

    // Compute r and rbar
    uint8_t r[32] = {0};
    bytes_t a = {.ptr = rng, .len = RNG_LEN};
    CHECK_PARSER_OK(h_star(a, randomizedPublicKey, transactionHash, r));
    CHECK_PARSER_OK(scalar_multiplication(r, SpendingKeyGenerator, rbar));

    // compute s and sbar
    uint8_t s[32] = {0};
    a.ptr = rbar;
    a.len = 32;
    CHECK_PARSER_OK(h_star(a, randomizedPublicKey, transactionHash, s));
    CHECK_PARSER_OK(compute_sbar(s, r, randomizedPrivateKey, sbar));

    MEMZERO(r, sizeof(r));
    MEMZERO(s, sizeof(s));

    return zxerr_ok;
}

#if defined(LEDGER_SPECIFIC)
parser_error_t crypto_get_ovk(uint8_t ovk[KEY_LENGTH]) {
    uint8_t buffer[4 * KEY_LENGTH] = {0};

    if (crypto_generateSaplingKeys(buffer, sizeof(buffer), ViewKeys) != zxerr_ok) {
        MEMZERO(buffer, sizeof(buffer));
        return parser_unexpected_error;
    }
    memcpy(ovk, buffer + 3 * KEY_LENGTH, KEY_LENGTH);
    MEMZERO(buffer, sizeof(buffer));
    return parser_ok;
}
#endif

parser_error_t crypto_decrypt_merkle_note(parser_tx_t *txObj, const uint8_t *m_note, const uint8_t ovk[KEY_LENGTH]) {
    if (ovk == NULL || m_note == NULL) {
        return parser_no_data;
    }

    uint8_t note_encryption_key[ENCRYPTED_SHARED_KEY_SIZE] = {0};
    if (decrypt_note_encryption_keys(ovk, m_note, note_encryption_key) != parser_ok) {
        MEMZERO(note_encryption_key, sizeof(note_encryption_key));
        return parser_unexpected_error;
    }

    uint8_t plain_text[ENCRYPTED_NOTE_SIZE] = {0};
    const uint8_t *ephemeral_public_key = m_note + VALUE_COMMITMENT_SIZE + NOTE_COMMITMENT_SIZE;
    if (decrypt_note(m_note, note_encryption_key + PUBLIC_ADDRESS_SIZE, note_encryption_key, ephemeral_public_key,
                     plain_text) != parser_ok) {
        MEMZERO(note_encryption_key, sizeof(note_encryption_key));
        MEMZERO(plain_text, sizeof(plain_text));
        return parser_unexpected_error;
    }

    txObj->outputs.decrypted_note.value = *(uint64_t *)(plain_text + SCALAR_SIZE);
    MEMCPY(txObj->outputs.decrypted_note.asset_id, plain_text + SCALAR_SIZE + AMOUNT_VALUE_SIZE + MEMO_SIZE,
           ASSET_ID_LENGTH);
    MEMCPY(txObj->outputs.decrypted_note.owner, note_encryption_key, PUBLIC_ADDRESS_SIZE);

    // Clear sensitive data
    MEMZERO(note_encryption_key, sizeof(note_encryption_key));
    MEMZERO(plain_text, sizeof(plain_text));
    return parser_ok;
}
