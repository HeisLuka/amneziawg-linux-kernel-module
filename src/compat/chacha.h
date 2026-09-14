#ifndef _AWG_COMPAT_CHACHA_H
#define _AWG_COMPAT_CHACHA_H

#include <linux/string.h>
#include <zinc/chacha20.h>

#define CHACHA_KEY_SIZE CHACHA20_KEY_SIZE
#define CHACHA_KEY_WORDS CHACHA20_KEY_WORDS

struct chacha_state {
	union {
		u32 x[CHACHA20_BLOCK_WORDS];
		struct chacha20_ctx ctx;
	};
};

static inline void chacha_init(struct chacha_state *state,
			       const u32 *key, const u8 *iv)
{
	state->x[0] = CHACHA20_CONSTANT_EXPA;
	state->x[1] = CHACHA20_CONSTANT_ND_3;
	state->x[2] = CHACHA20_CONSTANT_2_BY;
	state->x[3] = CHACHA20_CONSTANT_TE_K;
	memcpy(&state->x[4], key, CHACHA_KEY_SIZE);
	state->x[12] = get_unaligned_le32(iv + 0);
	state->x[13] = get_unaligned_le32(iv + 4);
	state->x[14] = get_unaligned_le32(iv + 8);
	state->x[15] = get_unaligned_le32(iv + 12);
}

static inline void chacha20_crypt(struct chacha_state *state, u8 *dst,
				  const u8 *src, unsigned int bytes)
{
	chacha20(&state->ctx, dst, src, bytes, DONT_USE_SIMD);
}

#endif
