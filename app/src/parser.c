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

#include "parser.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>

#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "parser_common.h"
#include "parser_impl.h"
#include "parser_print_common.h"
#include "rslib.h"

// lookup table for future use
static const asset_id_lookpup_t asset_id_lookups[] = {
    {{0x51, 0xf3, 0x3a, 0x2f, 0x14, 0xf9, 0x27, 0x35, 0xe5, 0x62, 0xdc, 0x65, 0x8a, 0x56, 0x39, 0x27,
      0x9d, 0xdc, 0xa3, 0xd5, 0x07, 0x9a, 0x6d, 0x12, 0x42, 0xb2, 0xa5, 0x88, 0xa9, 0xcb, 0xf4, 0x4c},
     8,
     " IRON"},
};

parser_error_t parser_check_outputs(parser_tx_t *tx_obj) {
    for (size_t i = 0; i < tx_obj->outputs.elements; i++) {
        // Decrypt the output
        const uint8_t *output = tx_obj->outputs.data.ptr + (i * (192 + 328));
        CHECK_ERROR(crypto_decrypt_merkle_note(tx_obj, output + 192, tx_obj->ovk));

        bool is_renderable = true;
        // If in expert mode show every output
        if (!app_mode_expert()) {
            // Verify the output owner
#if defined(LEDGER_SPECIFIC)
            is_renderable = MEMCMP(tx_obj->outputs.decrypted_note.owner, change_address, KEY_LENGTH) != 0;

#else
            is_renderable = true;
            uint8_t test_change_address[32] = {0x67, 0x3a, 0x8b, 0xfd, 0x38, 0xf9, 0x77, 0xea, 0x1e, 0x51, 0x1a,
                                               0x40, 0x65, 0x6d, 0x2a, 0x7a, 0x83, 0x22, 0x52, 0xbc, 0x40, 0xc1,
                                               0x4c, 0x27, 0x60, 0xad, 0x90, 0x64, 0x7d, 0x55, 0xb2, 0xef};
            is_renderable = MEMCMP(tx_obj->outputs.decrypted_note.owner, test_change_address, KEY_LENGTH) != 0;
#endif
        }

        if (!is_renderable) {
            tx_obj->output_render_mask &= ~(1ULL << i);  // Set the bit to 0 if equal
        } else {
            tx_obj->output_render_mask |= (1ULL << i);  // Set the bit to 1 if not equal
            tx_obj->n_rendered_outputs++;

            // If its renderable then we need to check if the asset ID is known
            bool asset_found = false;  // Track if asset ID is found
            for (size_t j = 0; j < sizeof(asset_id_lookups) / sizeof(asset_id_lookups[0]); j++) {
                if (MEMCMP(tx_obj->outputs.decrypted_note.asset_id, PIC(asset_id_lookups[j].identifier), 32) == 0) {
                    asset_found = true;  // Asset ID found
                    tx_obj->output_raw_asset_id_mask |= (1ULL << i);
                    break;
                }
            }

            // Handle case when asset ID is not found
            if (!asset_found) {
                tx_obj->output_raw_asset_id_mask &= ~(1ULL << i);
                tx_obj->n_raw_asset_id++;  // Increment if asset ID is not found
#if defined(LEDGER_SPECIFIC)
                // Check for expert mode if asset ID is not found
                if (!app_mode_expert()) {
                    return parser_require_expert_mode;
                }
#endif
            }
        }
    }
    return parser_ok;  // Return parser_ok after processing all outputs
}

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, parser_tx_t *tx_obj) {
    CHECK_ERROR(parser_init_context(ctx, data, dataLen));
    ctx->tx_obj = tx_obj;
    return _read(ctx, tx_obj);
}

uint64_t prev_decrypted_out_idx = 0;  // Previous decrypted output index

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems));

    prev_decrypted_out_idx = 0;

    char tmpKey[40] = {0};
    char tmpVal[40] = {0};

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount));
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    UNUSED(ctx);

    // Txversion + From + (owner + amount ) * output_with_valid_asset_id + (owner + amount + asset id) *
    // output_with_raw_asset_id + fee + expiration
    *num_items =
        2 + ((ctx->tx_obj->n_rendered_outputs - ctx->tx_obj->n_raw_asset_id) * 2) + (ctx->tx_obj->n_raw_asset_id * 3) + 2;

    if (*num_items == 0) {
        return parser_unexpected_number_items;
    }
    return parser_ok;
}

static void cleanOutput(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx) {
    if (displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    UNUSED(pageIdx);
    *pageCount = 1;
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems));
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx));
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    uint8_t tmp_idx = displayIdx;
    uint8_t asset_id_idx = 0;
    uint64_t cumulative_index = 0;
    uint64_t out_idx = 0;
    uint64_t out = 0;
    uint8_t n_item_out = 0;
    uint8_t total_output_items =
        ((ctx->tx_obj->n_rendered_outputs - ctx->tx_obj->n_raw_asset_id) * 2) + (ctx->tx_obj->n_raw_asset_id * 3);

    char buf[70] = {0};

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Tx Version");
        snprintf(outVal, outValLen, "V%d", (uint8_t)ctx->tx_obj->transactionVersion);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From");
#if defined(LEDGER_SPECIFIC)
        array_to_hexstr(buf, sizeof(buf), change_address, 32);
        pageString(outVal, outValLen, buf, pageIdx, pageCount);
#else
        uint8_t test_change_address[32] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
        array_to_hexstr(buf, sizeof(buf), test_change_address, 32);
        pageString(outVal, outValLen, buf, pageIdx, pageCount);
#endif
        return parser_ok;
    }

    tmp_idx -= 2;  // reset tmp_idx to first output screen
    // check if we are about to print outputs or we can move the the remmaining screens
    if (tmp_idx < total_output_items) {
        // Find the output that we are about to print
        for (out_idx = 0; out_idx < ctx->tx_obj->outputs.elements; out_idx++) {
            // check if the output is renderable
            if ((ctx->tx_obj->output_render_mask >> out_idx) & 1) {
                // check if the output has raw asset id so we can know how many items to print
                n_item_out = (ctx->tx_obj->output_raw_asset_id_mask >> out_idx & 1) ? 2 : 3;

                // if the display idx falls in the current output item range than break
                if (tmp_idx < cumulative_index + n_item_out) {
                    out = out_idx + 1;
                    break;
                }
                // update the cumulative index of ouput items
                cumulative_index += n_item_out;
            }
        }

        // Decrypt output if needed
        if (prev_decrypted_out_idx != out) {
            const uint8_t *output = ctx->tx_obj->outputs.data.ptr + ((out - 1) * (192 + 328));
            CHECK_ERROR(crypto_decrypt_merkle_note(ctx->tx_obj, output + 192, ctx->tx_obj->ovk));
            prev_decrypted_out_idx = out;  // Update previous decrypted index
        }

        // Generate output based on the local index
        uint8_t local_idx = tmp_idx - cumulative_index;
        switch (local_idx) {
            case 0:
                snprintf(outKey, outKeyLen, "To");
                array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->outputs.decrypted_note.owner, 32);
                pageString(outVal, outValLen, buf, pageIdx, pageCount);
                return parser_ok;

            case 1:
                if (ctx->tx_obj->output_raw_asset_id_mask >> (out - 1) & 1) {
                    snprintf(outKey, outKeyLen, "Amount");
                    CHECK_ERROR(
                        printAmount64(ctx->tx_obj->outputs.decrypted_note.value, asset_id_lookups[asset_id_idx].decimals,
                                      PIC(asset_id_lookups[asset_id_idx].name), outVal, outValLen, pageIdx, pageCount));
                    return parser_ok;
                } else {
                    snprintf(outKey, outKeyLen, "Raw amount");
                    uint64_to_str(buf, sizeof(buf), ctx->tx_obj->outputs.decrypted_note.value);
                    pageString(outVal, outValLen, buf, pageIdx, pageCount);
                    return parser_ok;
                }

            case 2:
                snprintf(outKey, outKeyLen, "Raw Asset ID");
                array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->outputs.decrypted_note.asset_id, 32);
                pageString(outVal, outValLen, buf, pageIdx, pageCount);
                return parser_ok;
        }
    }

    if (tmp_idx == total_output_items) {
        snprintf(outKey, outKeyLen, "Fee");
        CHECK_ERROR(printAmount64(ctx->tx_obj->fee, asset_id_lookups[0].decimals, PIC(asset_id_lookups[0].name), outVal,
                                  outValLen, pageIdx, pageCount));
        return parser_ok;
    }

    if (tmp_idx == total_output_items + 1) {
        snprintf(outKey, outKeyLen, "Expiration");
        uint32_to_str(buf, sizeof(buf), ctx->tx_obj->expiration);
        pageString(outVal, outValLen, buf, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_display_idx_out_of_range;  // If nothing matched
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_missing_field:
            return "missing field";

        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";
        case parser_require_expert_mode:
            return "Expert mode required";

        default:
            return "Unrecognized error code";
    }
}
