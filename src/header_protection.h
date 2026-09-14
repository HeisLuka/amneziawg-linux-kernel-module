#ifndef _AWG_HEADER_PROTECTION
#define _AWG_HEADER_PROTECTION

#include "messages.h"

#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#include "compat/chacha.h"
#else
#include <crypto/chacha.h>
#endif

struct wg_device;

enum header_protection_lengths {
    HEADER_PROTECTION_KEY_SIZE = CHACHA_KEY_SIZE,
    HEADER_PROTECTION_NONCE_SIZE = 12,
};

struct header_protection {
    u32 key[CHACHA_KEY_WORDS];
    struct rw_semaphore lock;
    bool has_protection;
};

bool awg_header_protection_init(struct chacha_state *state, struct wg_device *dev, u8 *nonce);
void awg_header_protection_set_key(struct header_protection *p, u8 key[HEADER_PROTECTION_KEY_SIZE]);
void awg_header_protection_get_key(struct header_protection *p, u8 key[HEADER_PROTECTION_KEY_SIZE]);

#endif
