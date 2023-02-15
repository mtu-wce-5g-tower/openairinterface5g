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

#ifndef SECU_DEFS_H_
#define SECU_DEFS_H_

#include "security_types.h"
#include <stdbool.h>
#include <stdint.h>

#define FC_KENB         (0x11)
#define FC_NH           (0x12)
#define FC_KENB_STAR    (0x13)
/* 33401 #A.7 Algorithm for key derivation function.
 * This FC should be used for:
 * - NAS Encryption algorithm
 * - NAS Integrity algorithm
 * - RRC Encryption algorithm
 * - RRC Integrity algorithm
 * - User Plane Encryption algorithm
 */
#define FC_ALG_KEY_DER  (0x15)
#define FC_KASME_TO_CK  (0x16)

#define NR_FC_ALG_KEY_DER  (0x69)
#define NR_FC_ALG_KEY_NG_RAN_STAR_DER  (0x70)

#ifndef hton_int32
# define hton_int32(x)   \
(((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) |  \
((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24))
#endif




#define EIA0_ALG_ID     0x00
#define EIA1_128_ALG_ID 0x01
#define EIA2_128_ALG_ID 0x02

#define EEA0_ALG_ID     0x00
#define EEA1_128_ALG_ID 0x01
#define EEA2_128_ALG_ID 0x02

#define SECU_DIRECTION_UPLINK   0
#define SECU_DIRECTION_DOWNLINK 1

int derive_keNB(const uint8_t kasme[32], const uint32_t nas_count, uint8_t *keNB);

int derive_keNB_star(const uint8_t *kenb_32, const uint16_t pci, const uint32_t earfcn_dl,
                      const bool is_rel8_only, uint8_t * kenb_star);

int derive_key_nas(algorithm_type_dist_t nas_alg_type, uint8_t nas_enc_alg_id,
                   const uint8_t kasme[32], uint8_t *knas);

#define derive_key_nas_enc(aLGiD, kASME, kNAS)  \
    derive_key_nas(NAS_ENC_ALG, aLGiD, kASME, kNAS)

#define derive_key_nas_int(aLGiD, kASME, kNAS)  \
    derive_key_nas(NAS_INT_ALG, aLGiD, kASME, kNAS)

#define derive_key_rrc_enc(aLGiD, kASME, kNAS)  \
    derive_key_nas(RRC_ENC_ALG, aLGiD, kASME, kNAS)

#define derive_key_rrc_int(aLGiD, kASME, kNAS)  \
    derive_key_nas(RRC_INT_ALG, aLGiD, kASME, kNAS)

#define derive_key_up_enc(aLGiD, kASME, kNAS)  \
    derive_key_nas(UP_ENC_ALG, aLGiD, kASME, kNAS)

#define derive_key_up_int(aLGiD, kASME, kNAS)  \
    derive_key_nas(UP_INT_ALG, aLGiD, kASME, kNAS)

#define SECU_DIRECTION_UPLINK   0
#define SECU_DIRECTION_DOWNLINK 1

typedef struct {
  uint8_t *key;
  uint32_t key_length;
  uint32_t count;
  uint8_t  bearer;
  uint8_t  direction;
  uint8_t  *message;
  /* length in bits */
  uint32_t  blength;
} nas_stream_cipher_t;

int nas_stream_encrypt_eea1(nas_stream_cipher_t *stream_cipher, uint8_t *out);

int nas_stream_encrypt_eia1(nas_stream_cipher_t *stream_cipher, uint8_t out[4]);

int nas_stream_encrypt_eea2(nas_stream_cipher_t *stream_cipher, uint8_t *out);

int nas_stream_encrypt_eia2(nas_stream_cipher_t *stream_cipher, uint8_t out[4]);

#undef SECU_DEBUG


int derive_skgNB(const uint8_t *keNB, const uint16_t sk_counter, uint8_t *skgNB);

void derive_key_alloca(algorithm_type_dist_t nas_alg_type, uint8_t nas_enc_alg_id,
               const uint8_t key[32], uint8_t **out);
int nr_derive_key(algorithm_type_dist_t alg_type, uint8_t alg_id,
               const uint8_t key[32], uint8_t **out);

int nr_derive_key_ng_ran_star(uint16_t pci, uint64_t nr_arfcn_dl, const uint8_t key[32], uint8_t *key_ng_ran_star);

//#define derive_key_nas_enc(aLGiD, kEY, kNAS)    derive_key_alloca(NAS_ENC_ALG, aLGiD, kEY, kNAS)

//#define derive_key_nas_int(aLGiD, kEY, kNAS)    derive_key_alloca(NAS_INT_ALG, aLGiD, kEY, kNAS)

#define derive_key_rrc_enc_osa(aLGiD, kEY, kNAS)  \
    derive_key_alloca(RRC_ENC_ALG, aLGiD, kEY, kNAS)

#define derive_key_rrc_int_osa(aLGiD, kEY, kNAS)  \
    derive_key_alloca(RRC_INT_ALG, aLGiD, kEY, kNAS)

#define derive_key_up_enc_osa(aLGiD, kEY, kNAS)  \
    derive_key_alloca(UP_ENC_ALG, aLGiD, kEY, kNAS)

#define derive_key_up_int_osa(aLGiD, kEY, kNAS)  \
    derive_key_alloca(UP_INT_ALG, aLGiD, kEY, kNAS)

// 5G SA
#define nr_derive_key_rrc_enc_osa(aLGiD, kEY, kRRC)  \
    nr_derive_key(RRC_ENC_ALG, aLGiD, kEY, kRRC)

#define nr_derive_key_rrc_int_osa(aLGiD, kEY, kRRC)  \
    nr_derive_key(RRC_INT_ALG, aLGiD, kEY, kRRC)

#define nr_derive_key_up_enc_osa(aLGiD, kEY, kUP)  \
    nr_derive_key(UP_ENC_ALG, aLGiD, kEY, kUP)

#define nr_derive_key_up_int_osa(aLGiD, kEY, kUP)  \
    nr_derive_key(UP_INT_ALG, aLGiD, kEY, kUP)








#endif /* SECU_DEFS_H_ */
