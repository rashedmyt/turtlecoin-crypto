// Copyright (c) 2020-2021, The TurtleCoin Developers
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef CRYPTO_H
#define CRYPTO_H

#include "base58.h"
#include "bulletproofs.h"
#include "bulletproofsplus.h"
#include "cn_base58.h"
#include "crypto_common.h"
#include "memory_helper.h"
#include "mnemonics.h"
#include "multisig.h"
#include "ring_signature_borromean.h"
#include "ring_signature_clsag.h"
#include "ringct.h"
#include "signature.h"

#include <cstdint>


// C Exports
extern "C"
{
    void base58_encode(const char *hex, char *output);
    void base58_encode_check(const char *hex, char *output);
    void base58_decode(const char *base58, char *output);
    void base58_decode_check(const char *base58, char *output);

    void cn_base58_encode(const char *hex, char *output);
    void cn_base58_encode_check(const char *hex, char *output);
    void cn_base58_decode(const char *base58, char *output);
    void cn_base58_decode_check(const char *base58, char *output);

    bool borromean_check_ring_signature(
        const char *message_digest,
        const char *key_image,
        const char **public_keys,
        const char *signature);
    void borromean_complete_ring_signature(
        const char *signing_scalar,
        const uint64_t real_output_index,
        const char *signature,
        const char **partial_signing_scalars,
        char *output);
    void borromean_generate_partial_signing_scalar(
        const uint64_t real_output_index,
        const char *signature,
        const char *secret_spend_key,
        char *output);
    void borromean_generate_ring_signature(
        const char *message_digest,
        const char *secret_ephemeral,
        const char **public_keys,
        char *output);
    void borromean_prepare_ring_signature(
        const char *message_digest,
        const char *key_image,
        const char **public_keys,
        const uint64_t real_output_index,
        char *output);

    void bulletproofs_prove(const uint64_t *amounts, const char **blinding_factors, char *proofs, char **commitments);
    bool bulletproofs_verify(const char *proofs, const char **commitments);

    void bulletproofsplus_prove(
        const uint64_t *amounts,
        const char **blinding_factors,
        char *proofs,
        char **commitments);
    bool bulletproofsplus_verify(const char *proofs, const char **commitments);

    bool clsag_check_ring_signature(
        const char *message_digest,
        const char *key_image,
        const char **public_keys,
        const char *signature,
        const char **commitments);
    void clsag_complete_ring_signature(
        const char *signing_scalar,
        const uint64_t real_output_index,
        const char *signature,
        const char **h,
        const char *mu_P,
        const char **partial_signing_scalars,
        char *output);
    void clsag_generate_partial_ring_signature(const char *mu_P, const char *secret_spend_key, char *output);
    void clsag_generate_ring_signature(
        const char *message_digest,
        const char *secret_ephemeral,
        const char **public_keys,
        const char *input_blinding_factor,
        const char **public_commitments,
        const char *pseudo_blinding_factor,
        const char *pseudo_commitment,
        char *output);
    void clsag_prepare_ring_signature(
        const char *message_digest,
        const char *key_image,
        const char **public_keys,
        const uint64_t real_output_index,
        const char *input_blinding_factor,
        const char **public_commitments,
        const char *pseudo_blinding_factor,
        const char *pseudo_commitment,
        char *signature,
        char **h,
        char *mu_P);

    void argon2d(
        const char *input,
        const uint64_t iterations,
        const uint64_t memory,
        const uint64_t threads,
        char *output);
    void argon2i(
        const char *input,
        const uint64_t iterations,
        const uint64_t memory,
        const uint64_t threads,
        char *output);
    void argon2id(
        const char *input,
        const uint64_t iterations,
        const uint64_t memory,
        const uint64_t threads,
        char *output);
    void sha3(const char *input, char *output);
    void sha3_slow_hash(const char *input, const uint64_t iterations, char *output);
    void root_hash(const char **hashes, char *output);
    void root_hash_from_branch(
        const char **branches,
        const uint64_t depth,
        const char *leaf,
        const uint64_t path,
        char *output);
    void tree_branch(const char **hashes, char *output);
    uint64_t tree_depth(const uint64_t count);

    void generate_multisig_secret_key(const char *their_public_key, const char *our_secret_key, char *output);
    void generate_multisig_secret_keys(const char **their_public_key, const char *our_secret_key, char **output);
    void generate_shared_public_key(const char **public_keys, char *output);
    void generate_shared_secret_key(const char **secret_keys, char *output);
    uint64_t rounds_required(const uint64_t participants, const uint64_t threshold);

    uint64_t mnemonics_calculate_checksum_index(const char **words);
    uint64_t mnemonics_decode(const char **words, char *string);
    void mnemonics_encode(const char *seed, const uint64_t timestamp, const bool auto_timestamp, char **output);
    uint64_t mnemonics_word_index(const char *word);
    void mnemonics_word_list(const char **output);
    void mnemonics_word_list_trimmed(const char **output);

    bool check_commitments_parity(
        const char **pseudo_commitments,
        const char **output_commitments,
        const uint64_t transaction_fee);
    void generate_amount_mask(const char *derivation_scalar, char *output);
    void generate_commitment_blinding_factor(const char *derivation_scalar, char *output);
    void generate_pedersen_commitment(const char *blinding_factor, const uint64_t amount, char *output);
    void generate_pseudo_commitments(
        const uint64_t *amounts,
        const char *output_blinding_factors,
        char **output1,
        char **output2);
    void generate_transaction_fee_commitment(const uint64_t amount, char *output);
    uint64_t toggle_masked_amount(const char *amount_mask, const uint64_t amount);

    bool check_signature(const char *message_digest, const char *public_key, const char *signature);
    void complete_signature(
        const char *signing_scalar,
        const char *signature,
        const char **partial_signing_scalars,
        char *output);
    void generate_partial_signing_scalar(const char *signature, const char *secret_spend_key, char *output);
    void generate_signature(const char *message_digest, const char *secret_key, char *output);
    void prepare_signature(const char *message_digest, const char *public_key, char *output);

    uint64_t calculate_base2_exponent(const uint64_t value);
    bool check_point(const char *point);
    bool check_scalar(const char *scalar);
    void derivation_to_scalar(const char *derivation, const uint64_t output_index, char *output);
    void derive_public_key(const char *derivation_scalar, const char *public_key, char *output);
    void derive_secret_key(const char *derivation_scalar, const char *secret_key, char *output);
    void generate_key_derivation(const char *public_key, const char *secret_key, char *output);
    void generate_key_image(
        const char *public_ephemeral,
        const char *secret_ephemeral,
        const char **partial_key_images,
        char *output);
    void generate_key_image_v2(const char *secret_ephemeral, char *output);
    void generate_keys(char *output1, char *output2);
    uint64_t generate_wallet_seed(const char *entropy, char *output1, char **output2);
    void generate_wallet_spend_keys(
        const char *secret_spend_key,
        const uint64_t subwallet_index,
        char *output1,
        char *output2);
    void generate_wallet_view_keys(const char *secret_spend_key, char *output1, char *output2);
    void hash_to_point(const char *input, char *output);
    void hash_to_scalar(const char *input, char *output);
    uint64_t pow2_round(const uint64_t value);
    void random_point(char *output);
    void random_points(const uint64_t count, char **output);
    void random_scalar(char *output);
    void random_scalars(const uint64_t count, char **output);
    uint64_t restore_wallet_seed(const char **words, char *output);
    void secret_key_to_public_key(const char *secret_key, char *output);
    void underive_public_key(
        const char *derivation,
        const uint64_t output_index,
        const char *public_ephemeral,
        char *output);
}

#endif // CRYPTO_H
