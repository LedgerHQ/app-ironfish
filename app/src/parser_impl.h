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
#pragma once

#include <zxmacros.h>

#include "parser_common.h"
#include "parser_txdef.h"
#include "zxtypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ELEMENTS_PER_OUTPUT   2
#define OUTPUT_ELEMENT_OFFSET 1
/**
 * @brief Checks that there are at least SIZE bytes available in the buffer.
 * @param CTX Context
 * @param SIZE Size to check
 * @return parser_error_t Error code
 */
#define CTX_CHECK_AVAIL(CTX, SIZE)                                      \
    if ((CTX) == NULL || ((CTX)->offset + (SIZE)) > (CTX)->bufferLen) { \
        return parser_unexpected_buffer_end;                            \
    }

parser_error_t _read(parser_context_t *c, parser_tx_t *v);

#ifdef __cplusplus
}
#endif
