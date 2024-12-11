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
#include "parser_print_common.h"

#include <zxformat.h>
#include <zxmacros.h>

#include "coin.h"

void remove_fraction(char *s) {
    size_t len = strlen(s);

    // Find the decimal point
    char *decimal_point = strchr(s, '.');
    if (decimal_point == NULL) {
        // No decimal point found, nothing to remove
        return;
    }

    // Find the end of the string up to the decimal point
    size_t end_index = decimal_point - s;

    // Find the first non-zero digit after the decimal point
    size_t non_zero_index = end_index + 1;
    while (s[non_zero_index] == '0') {
        non_zero_index++;
    }

    // Check if there is a non-zero digit after the decimal point
    if (non_zero_index >= len) {
        // There is no non-zero digit after the decimal point
        // Remove the decimal point and trailing zeros
        s[end_index] = '\0';
    }
}

parser_error_t printAmount64(uint64_t amount, uint8_t amount_decimals, const char *symbol, char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {
    char strAmount[33] = {0};
    if (uint64_to_str(strAmount, sizeof(strAmount), amount) != NULL) {
        return parser_unexpected_error;
    }
    if (intstr_to_fpstr_inplace(strAmount, sizeof(strAmount), amount_decimals) == 0) {
        return parser_unexpected_error;
    }

    number_inplace_trimming(strAmount, 1);
    remove_fraction(strAmount);
    z_str3join(strAmount, sizeof(strAmount), "", symbol);
    pageString(outVal, outValLen, strAmount, pageIdx, pageCount);

    return parser_ok;
}
