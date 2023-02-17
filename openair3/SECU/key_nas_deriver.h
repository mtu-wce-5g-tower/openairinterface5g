#ifndef KEY_NAS_DERIVER_H
#define KEY_NAS_DERIVER_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "security_types.h"


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

void derive_keNB(const uint8_t kasme[32], const uint32_t nas_count, uint8_t *keNB);

void derive_keNB_star(const uint8_t *kenb_32, const uint16_t pci, const uint32_t earfcn_dl,
                      const bool is_rel8_only, uint8_t * kenb_star);

void derive_key_nas(algorithm_type_dist_t nas_alg_type, uint8_t nas_enc_alg_id,
                   const uint8_t kasme[32], uint8_t *knas);

void derive_skgNB(const uint8_t *keNB, const uint16_t sk_counter, uint8_t *skgNB);

void derive_key_alloca(algorithm_type_dist_t nas_alg_type, uint8_t nas_enc_alg_id,
               const uint8_t key[32], uint8_t **out);

void nr_derive_key(algorithm_type_dist_t alg_type, uint8_t alg_id,
               const uint8_t key[32], uint8_t **out);

void nr_derive_key_ng_ran_star(uint16_t pci, uint64_t nr_arfcn_dl, const uint8_t key[32], uint8_t *key_ng_ran_star);


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

#endif

