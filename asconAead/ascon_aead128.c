/**
 * @file
 * 64-bit optimised implementation of Ascon128 AEAD cipher.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "../ascon.h"
#include "../ascon_internal.h"
#include "stdio.h"

ASCON_API void
ascon_aead128_encrypt(ascon_aead_ctx_t* ctx,
                      const uint8_t* assoc_data,
                      const uint8_t* plaintext,
                      size_t assoc_data_len,
                      size_t plaintext_len,
                      uint8_t* ciphertext,
                      uint8_t* tag,
                      size_t tag_len)
{
    ASCON_ASSERT(plaintext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(tag_len != 0 || tag != NULL);
    ASCON_ASSERT(key != NULL);
    ASCON_ASSERT(nonce != NULL);
    ASCON_ASSERT(assoc_data_len == 0 || assoc_data != NULL);
    ASCON_ASSERT(plaintext_len == 0 || plaintext != NULL);

    ascon_aead_ctx_t temp_ctx;
    memcpy(&temp_ctx, ctx, sizeof(ascon_aead_ctx_t));

    ascon_aead128_assoc_data_update(&temp_ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128_encrypt_update(&temp_ctx, ciphertext,
                                                             plaintext,
                                                             plaintext_len);
    ascon_aead128_encrypt_final(&temp_ctx, ciphertext + new_ct_bytes,
                                tag, tag_len);
}

ASCON_API bool
ascon_aead128_decrypt(ascon_aead_ctx_t* ctx,
                      uint8_t* plaintext,
                      const uint8_t* assoc_data,
                      const uint8_t* ciphertext,
                      const uint8_t* expected_tag,
                      size_t assoc_data_len,
                      size_t ciphertext_len,
                      size_t expected_tag_len)
{
    ASCON_ASSERT(ciphertext_len == 0 || plaintext != NULL);
    ASCON_ASSERT(key != NULL);
    ASCON_ASSERT(nonce != NULL);
    ASCON_ASSERT(assoc_data_len == 0 || assoc_data != NULL);
    ASCON_ASSERT(ciphertext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(expected_tag_len != 0 || expected_tag != NULL);

    ascon_aead_ctx_t temp_ctx;
    memcpy(&temp_ctx, ctx, sizeof(ascon_aead_ctx_t));

    bool is_tag_valid;
    // ascon_aead128_init(ctx, key, nonce);
    ascon_aead128_assoc_data_update(&temp_ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128_decrypt_update(&temp_ctx,
                                                             plaintext,
                                                             ciphertext,
                                                             ciphertext_len);
    ascon_aead128_decrypt_final(&temp_ctx, plaintext + new_pt_bytes,
                                &is_tag_valid, expected_tag, expected_tag_len);
    return is_tag_valid;
}

ASCON_API void
ascon_aead128_init(ascon_aead_ctx_t* const ctx,
                   const uint8_t key[ASCON_AEAD128_KEY_LEN],
                   const uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(key != NULL);
    ASCON_ASSERT(nonce != NULL);
    ascon_aead_init(ctx, key, nonce, ASCON_IV_AEAD128);
    ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_INITIALISED;
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the associated data to
 * be authenticated, both during encryption and decryption.
 */
static void
absorb_assoc_data(ascon_sponge_t* sponge,
                  uint8_t* const data_out,
                  const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bigendian_decode_u64(data);
    ascon_permutation_6(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the ciphertext
 * and squeeze out plaintext during decryption.
 */
static void
absorb_ciphertext(ascon_sponge_t* const sponge,
                  uint8_t* const plaintext,
                  const uint8_t* const ciphertext)
{
    // Absorb the ciphertext.
    const uint64_t c_0 = bigendian_decode_u64(ciphertext);
    // Squeeze out some plaintext
    bigendian_encode_u64(plaintext, sponge->x0 ^ c_0);
    sponge->x0 = c_0;
    // Permute the state
    ascon_permutation_6(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the plaintext
 * and squeeze out ciphertext during encryption.
 */
static void
absorb_plaintext(ascon_sponge_t* const sponge,
                 uint8_t* const ciphertext,
                 const uint8_t* const plaintext)
{
    // Absorb the plaintext.
    sponge->x0 ^= bigendian_decode_u64(plaintext);
    // Squeeze out some ciphertext
    bigendian_encode_u64(ciphertext, sponge->x0);
    // Permute the state
    ascon_permutation_6(sponge);
}

ASCON_API void
ascon_aead128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(assoc_data_len == 0 || assoc_data != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED);
    if (assoc_data_len > 0)
    {
        ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED;
        buffered_accumulation(&ctx->bufstate, NULL, assoc_data,
                              absorb_assoc_data, assoc_data_len, ASCON_RATE);
    }
}

ASCON_API size_t
ascon_aead128_encrypt_update(ascon_aead_ctx_t* const ctx,
                             uint8_t* ciphertext,
                             const uint8_t* plaintext,
                             size_t plaintext_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(plaintext_len == 0 || plaintext != NULL);
    ASCON_ASSERT(plaintext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED;
    // Start absorbing plaintext and simultaneously squeezing out ciphertext
    return buffered_accumulation(&ctx->bufstate, ciphertext, plaintext,
                                 absorb_plaintext, plaintext_len, ASCON_RATE);
}

ASCON_API size_t
ascon_aead128_encrypt_final(ascon_aead_ctx_t* const ctx,
                            uint8_t* const ciphertext,
                            uint8_t* tag,
                            size_t tag_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(ciphertext != NULL);
    ASCON_ASSERT(tag_len == 0 || tag != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED);
    
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_ciphertext_len = 0;
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->bufstate.sponge.x0 ^= bigendian_decode_varlen(ctx->bufstate.buffer,
                                                       ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    // Squeeze out last ciphertext bytes, if any.
    bigendian_encode_varlen(ciphertext, ctx->bufstate.sponge.x0, ctx->bufstate.buffer_len);
    freshly_generated_ciphertext_len += ctx->bufstate.buffer_len;
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    // Squeeze out tag into its buffer.
    ascon_aead_generate_tag(ctx, tag, tag_len);
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead_cleanup(ctx);
    return freshly_generated_ciphertext_len;
}

ASCON_API size_t
ascon_aead128_encrypt_intermediate(ascon_aead_ctx_t* const ctx,
                            uint8_t* const ciphertext,
                            uint8_t* tag,
                            size_t tag_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(ciphertext != NULL);
    ASCON_ASSERT(tag_len == 0 || tag != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED);

    ascon_aead_ctx_t temp_ctx;
    memcpy(&temp_ctx, ctx, sizeof(ascon_aead_ctx_t));
    
    if (temp_ctx.bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(&temp_ctx);
    }
    size_t freshly_generated_ciphertext_len = 0;
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    temp_ctx.bufstate.sponge.x0 ^= bigendian_decode_varlen(temp_ctx.bufstate.buffer,
                                                       temp_ctx.bufstate.buffer_len);
    temp_ctx.bufstate.sponge.x0 ^= PADDING(temp_ctx.bufstate.buffer_len);
    // Squeeze out last ciphertext bytes, if any.
    bigendian_encode_varlen(ciphertext, temp_ctx.bufstate.sponge.x0, temp_ctx.bufstate.buffer_len);
    freshly_generated_ciphertext_len += temp_ctx.bufstate.buffer_len;
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    temp_ctx.bufstate.sponge.x1 ^= temp_ctx.k0;
    temp_ctx.bufstate.sponge.x2 ^= temp_ctx.k1;
    ascon_permutation_12(&temp_ctx.bufstate.sponge);
    temp_ctx.bufstate.sponge.x3 ^= temp_ctx.k0;
    temp_ctx.bufstate.sponge.x4 ^= temp_ctx.k1;
    // Squeeze out tag into its buffer.
    ascon_aead_generate_tag(&temp_ctx, tag, tag_len);
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead_cleanup(&temp_ctx);
    return freshly_generated_ciphertext_len;
}


ASCON_API size_t
ascon_aead128_decrypt_update(ascon_aead_ctx_t* const ctx,
                             uint8_t* plaintext,
                             const uint8_t* ciphertext,
                             size_t ciphertext_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(ciphertext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(ciphertext_len == 0 || plaintext != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED;
    // Start absorbing ciphertext and simultaneously squeezing out plaintext
    return buffered_accumulation(&ctx->bufstate, plaintext, ciphertext,
                                 absorb_ciphertext, ciphertext_len, ASCON_RATE);
}

ASCON_API size_t
ascon_aead128_decrypt_final(ascon_aead_ctx_t* const ctx,
                            uint8_t* plaintext,
                            bool* const is_tag_valid,
                            const uint8_t* const expected_tag,
                            size_t expected_tag_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(plaintext != NULL);
    ASCON_ASSERT(expected_tag_len == 0 || expected_tag != NULL);
    ASCON_ASSERT(is_tag_valid != NULL);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    const uint64_t c_0 = bigendian_decode_varlen(ctx->bufstate.buffer,
                                                 ctx->bufstate.buffer_len);
    // Squeeze out last plaintext bytes, if any.
    bigendian_encode_varlen(plaintext, ctx->bufstate.sponge.x0 ^ c_0,
                            ctx->bufstate.buffer_len);
    freshly_generated_plaintext_len += ctx->bufstate.buffer_len;
    // Final state changes at decryption's end
    ctx->bufstate.sponge.x0 &= ~mask_most_signif_bytes(ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 |= c_0;
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    // Validate tag with variable len
    *is_tag_valid = ascon_aead_is_tag_valid(ctx, expected_tag, expected_tag_len);
    // Final security cleanup of the internal state and key.
    ascon_aead_cleanup(ctx);
    free(ctx);
    return freshly_generated_plaintext_len;
}

ASCON_API size_t
ascon_aead128_decrypt_intermediate(ascon_aead_ctx_t* const ctx,
                            uint8_t* plaintext,
                            uint8_t* tag,
                            size_t tag_len)
{
    ascon_aead_ctx_t temp_ctx;
    memcpy(&temp_ctx, ctx, sizeof(ascon_aead_ctx_t));

    if (temp_ctx.bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    const uint64_t c_0 = bigendian_decode_varlen(temp_ctx.bufstate.buffer,
                                                 temp_ctx.bufstate.buffer_len);
    // Squeeze out last plaintext bytes, if any.
    bigendian_encode_varlen(plaintext, temp_ctx.bufstate.sponge.x0 ^ c_0,
                            temp_ctx.bufstate.buffer_len);
    freshly_generated_plaintext_len += temp_ctx.bufstate.buffer_len;
    // Final state changes at decryption's end
    temp_ctx.bufstate.sponge.x0 &= ~mask_most_signif_bytes(temp_ctx.bufstate.buffer_len);
    temp_ctx.bufstate.sponge.x0 |= c_0;
    temp_ctx.bufstate.sponge.x0 ^= PADDING(temp_ctx.bufstate.buffer_len);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    temp_ctx.bufstate.sponge.x1 ^= temp_ctx.k0;
    temp_ctx.bufstate.sponge.x2 ^= temp_ctx.k1;
    ascon_permutation_12(&temp_ctx.bufstate.sponge);
    temp_ctx.bufstate.sponge.x3 ^= temp_ctx.k0;
    temp_ctx.bufstate.sponge.x4 ^= temp_ctx.k1;

    // Squeeze out tag into its buffer.
    ascon_aead_generate_tag(&temp_ctx, tag, tag_len);

    // Final security cleanup of the internal state and key.
    ascon_aead_cleanup(&temp_ctx);
    return freshly_generated_plaintext_len;
}

