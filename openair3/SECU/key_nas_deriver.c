/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common/utils/assertions.h"

#include "security_types.h"
#include "secu_defs.h"
#include "kdf.h"



#define SECU_DEBUG 1
/*!
 * @brief Derive the kNASenc from kasme and perform truncate on the generated key to
 * reduce his size to 128 bits. Definition of the derivation function can
 * be found in 3GPP TS.33401 #A.7
 * @param[in] nas_alg_type NAS algorithm distinguisher
 * @param[in] nas_enc_alg_id NAS encryption/integrity algorithm identifier.
 * Possible values are:
 *      - 0 for EIA0 algorithm (Null Integrity Protection algorithm)
 *      - 1 for 128-EIA1 SNOW 3G
 *      - 2 for 128-EIA2 AES
 * @param[in] kasme Key for MME as provided by AUC
 * @param[out] knas Pointer to reference where output of KDF will be stored.
 */
int derive_key_nas(algorithm_type_dist_t nas_alg_type, uint8_t nas_enc_alg_id,
                   const uint8_t kasme[32], uint8_t *knas)
{
  uint8_t s[7];
  uint8_t out[32];
#if defined(SECU_DEBUG)
  int i;
#endif

  /* FC */
  s[0] = FC_ALG_KEY_DER;

  /* P0 = algorithm type distinguisher */
  s[1] = (uint8_t)(nas_alg_type & 0xFF);

  /* L0 = length(P0) = 1 */
  s[2] = 0x00;
  s[3] = 0x01;

  /* P1 */
  s[4] = nas_enc_alg_id;

  /* L1 = length(P1) = 1 */
  s[5] = 0x00;
  s[6] = 0x01;

#if defined(SECU_DEBUG)
  printf("%s FC %d nas_alg_type distinguisher %d nas_enc_alg_identity %d\n",
         __FUNCTION__, FC_ALG_KEY_DER, nas_alg_type, nas_enc_alg_id);

  for (i = 0; i < 7; i ++) {
    printf("0x%02x ", s[i]);
  }

  printf("\n");
#endif

  //kdf(kasme, 32, s, 7, out, 32);
  byte_array_t data = {.len = 7, .buf = s};
  kdf(kasme, data, 32, out);

  memcpy(knas, &out[31-16+1], 16);

  return 0;
}




/*!
 * @brief Derive the keys from key and perform truncate on the generated key to
 * reduce his size to 128 bits. Definition of the derivation function can
 * be found in 3GPP TS.33401 #A.7
 * @param[in] alg_type Algorithm distinguisher
 * @param[in] alg_id Algorithm identifier.
 * Possible values are:
 *      - 0 for EIA0 algorithm (Null Integrity Protection algorithm)
 *      - 1 for 128-EIA1 SNOW 3G
 *      - 2 for 128-EIA2 AES
 * @param[in] key The top key used to derive other subkeys
 * @param[out] out Pointer to reference where output of KDF will be stored.
 * NOTE: knas is dynamically allocated by the KDF function
 */
void derive_key_alloca(algorithm_type_dist_t alg_type, uint8_t alg_id, const uint8_t key[32], uint8_t **out)
{
  uint8_t string[7] = {0};

  /* FC */
  string[0] = FC_ALG_KEY_DER;

  /* P0 = algorithm type distinguisher */
  string[1] = (uint8_t)(alg_type & 0xFF);

  /* L0 = length(P0) = 1 */
  string[2] = 0x00;
  string[3] = 0x01;

  /* P1 */
  string[4] = alg_id;

  /* L1 = length(P1) = 1 */
  string[5] = 0x00;
  string[6] = 0x01;

#if defined(SECU_DEBUG)
  {
    int i;
    char payload[6 * sizeof(string) + 1];
    int index = 0;

    for (i = 0; i < sizeof(string); i++)
      index += sprintf(&payload[index], "0x%02x ", string[i]);

//    LOG_D(OSA, "Key deriver input string: %s\n", payload);
  }
#endif

  byte_array_t data = {.buf = string, .len = 7};
  if (*out == NULL) {
    *out = malloc(sizeof(uint8_t) * 32);
    DevAssert(*out != NULL && "Memory exhausted");
  }
  kdf(key, data, 32, *out);

}

int nr_derive_key(algorithm_type_dist_t alg_type, uint8_t alg_id, const uint8_t key[32], uint8_t **out)
{
  uint8_t string[7];

  /* FC */
  string[0] = NR_FC_ALG_KEY_DER;

  /* P0 = algorithm type distinguisher */
  string[1] = (uint8_t)(alg_type & 0xFF);

  /* L0 = length(P0) = 1 */
  string[2] = 0x00;
  string[3] = 0x01;

  /* P1 */
  string[4] = alg_id;

  /* L1 = length(P1) = 1 */
  string[5] = 0x00;
  string[6] = 0x01;

  byte_array_t data = {.buf = string, .len = 7};

  if (*out == NULL) {
    *out = malloc(sizeof(uint8_t) * 32);
    DevAssert(*out != NULL && "Memory exhausted");
  }
  kdf(key, data, 32, *out);

  // in NR, we use the last 16 bytes, ignoring the first 16 ones
  memcpy(*out, *out + 16, 16);

  return 0;
}

int nr_derive_key_ng_ran_star(uint16_t pci, uint64_t nr_arfcn_dl, const uint8_t key[32], uint8_t *key_ng_ran_star)
{
  uint8_t s[10] = {0};

  /* FC */
  s[0] = NR_FC_ALG_KEY_NG_RAN_STAR_DER;

  /* P0 = PCI */
  s[1] = (pci & 0x0000ff00) >> 8;
  s[2] = (pci & 0x000000ff);

  /* L0 = length(P0) = 2 */
  s[3] = 0x00;
  s[4] = 0x02;

  /* P1 = NR ARFCN */
  s[5] = (nr_arfcn_dl & 0x00ff0000) >> 16;
  s[6] = (nr_arfcn_dl & 0x0000ff00) >> 8;
  s[7] = (nr_arfcn_dl & 0x000000ff);

  /* L1 = length(P1) = 3 */
  s[8] = 0x00;
  s[9] = 0x03;


  byte_array_t data = {.buf = s, .len = 10};
  const uint32_t len_key = 32;
  kdf(key, data, len_key, key_ng_ran_star);

  return 0;
}

int derive_skgNB(const uint8_t *keNB, const uint16_t sk_counter, uint8_t *skgNB)
{
  uint8_t s[5] = {0};

  /* FC is 0x1c (see 3gpp 33.401 annex A.15) */
  s[0] = 0x1c;

  /* put sk_counter */
  s[1] = (sk_counter >> 8) & 0xff;
  s[2] = sk_counter & 0xff;

  /* put length of sk_counter (2) */
  s[3] = 0x00;
  s[4] = 0x02;

  byte_array_t data = {.buf = s, .len = 5};
  kdf(keNB, data, 32, skgNB);

  return 0;
}







