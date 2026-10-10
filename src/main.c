#include "codboz_frame_interpolation.h"
#include "s3e_host.h"
#include "s3e_image.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#if defined(__arm__)
static uintptr_t g_loaded_base;
static const char g_empty_string[8] __attribute__((aligned(8))) = "";
static uint32_t g_bucket_allocator_table[33] __attribute__((aligned(8)));
#endif

#if defined(__arm__)
enum {
    BUCKET_ALLOCATOR_TABLE_SLOT = 0x4cu,
};

static void attach_bucket_allocator_table(uint32_t object) {
    uint32_t *table_slot = (uint32_t *)(uintptr_t)(object + BUCKET_ALLOCATOR_TABLE_SLOT);
    *table_slot = (uint32_t)(uintptr_t)g_bucket_allocator_table;
}

static void prepare_bucket_allocator_table(uint32_t object) {
    if (!object) {
        return;
    }

    attach_bucket_allocator_table(object);
    memset(g_bucket_allocator_table, 0, sizeof(g_bucket_allocator_table));
}
#endif

#if defined(__arm__)
static bool recover_bucket_allocator_fault(ucontext_t *uc) {
    uintptr_t pc = uc->uc_mcontext.arm_pc;
    if (pc != g_loaded_base + 0x374be8u && pc != g_loaded_base + 0x374bf4u) {
        return false;
    }

    uint32_t object = uc->uc_mcontext.arm_r5 ? uc->uc_mcontext.arm_r5 : uc->uc_mcontext.arm_r0;
    uint32_t index = uc->uc_mcontext.arm_r4 ? uc->uc_mcontext.arm_r4 : uc->uc_mcontext.arm_r1;
    if (!object) {
        return false;
    }
    if (index >= 32 && pc == g_loaded_base + 0x374be8u) {
        index = 1;
    }
    if (index >= 32) {
        return false;
    }

    attach_bucket_allocator_table(object);

    uc->uc_mcontext.arm_r0 = object;
    uc->uc_mcontext.arm_r1 = index;
    uc->uc_mcontext.arm_r2 = (uint32_t)(uintptr_t)g_bucket_allocator_table;
    uc->uc_mcontext.arm_r4 = index;
    uc->uc_mcontext.arm_r5 = object;

    if (pc == g_loaded_base + 0x374be8u) {
        prepare_bucket_allocator_table(object);
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x374be8u;
    } else {
        g_bucket_allocator_table[index] = 0;
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x374c34u;
    }
    return true;
}

static bool recover_null_buffer_write(ucontext_t *uc) {
    if (uc->uc_mcontext.arm_pc != g_loaded_base + 0xcb8eeu || uc->uc_mcontext.arm_r0 != 0) {
        return false;
    }

    uint32_t *sp = (uint32_t *)(uintptr_t)uc->uc_mcontext.arm_sp;
    uc->uc_mcontext.arm_r4 = sp[0];
    uc->uc_mcontext.arm_r5 = sp[1];
    uc->uc_mcontext.arm_r6 = sp[2];
    uc->uc_mcontext.arm_r0 = 0;
    uc->uc_mcontext.arm_sp += 16;
    uc->uc_mcontext.arm_pc = sp[3] & ~1u;
    return true;
}

static bool recover_null_buffer_slot(ucontext_t *uc) {
    uintptr_t pc = uc->uc_mcontext.arm_pc;
    if ((pc != g_loaded_base + 0xd291cu && pc != g_loaded_base + 0xd293au) ||
        uc->uc_mcontext.arm_r2 != 0) {
        return false;
    }

    uint32_t *sp = (uint32_t *)(uintptr_t)uc->uc_mcontext.arm_sp;
    uc->uc_mcontext.arm_r3 = sp[0];
    uc->uc_mcontext.arm_r4 = sp[1];
    uc->uc_mcontext.arm_r5 = sp[2];
    uc->uc_mcontext.arm_r6 = sp[3];
    uc->uc_mcontext.arm_r7 = sp[4];
    uc->uc_mcontext.arm_r0 = 0;
    uc->uc_mcontext.arm_sp += 24;
    uc->uc_mcontext.arm_pc = sp[5] & ~1u;
    return true;
}

#endif

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [--run] [--diagnostic-skip-frame-interpolation] [--root DIR] [--display-size WIDTHxHEIGHT] "
            "IMAGE.s3e.unpacked\n",
            argv0);
}

static bool parse_display_size(const char *value, uint32_t *width, uint32_t *height) {
    char *width_end = NULL;
    char *height_end = NULL;
    unsigned long parsed_width = strtoul(value, &width_end, 10);
    if (width_end == value || (*width_end != 'x' && *width_end != 'X')) {
        return false;
    }
    unsigned long parsed_height = strtoul(width_end + 1, &height_end, 10);
    if (height_end == width_end + 1 || *height_end != '\0' || !parsed_width || !parsed_height ||
        parsed_width > UINT16_MAX || parsed_height > UINT16_MAX) {
        return false;
    }
    *width = (uint32_t)parsed_width;
    *height = (uint32_t)parsed_height;
    return true;
}

#if defined(__arm__)
static uint16_t g_d8ff0_saved;
static uint16_t g_da6c6_saved;
static uint16_t g_d8ffa_saved;
static uint16_t g_d8984_saved;
static uint32_t g_arm_dispatch_saved;
static uint32_t g_arm_callsite_saved;
static uint32_t g_arm_return_saved;
static unsigned g_arm_dispatch_call_seq;
#define BOZ_ARM_ALLOC_TRACE_MAX 96u
static uint32_t g_arm_call_size[BOZ_ARM_ALLOC_TRACE_MAX];
static uint32_t g_arm_call_lr[BOZ_ARM_ALLOC_TRACE_MAX];
static uint32_t g_arm_return_r0[BOZ_ARM_ALLOC_TRACE_MAX];
static int g_arm_dispatch_trace_armed;
static int g_arm_callsite_trace_armed;
static int g_arm_return_trace_armed;
static int g_d8ff0_trace_armed;
static int g_da6c6_trace_armed;
static int g_d8ffa_trace_armed;
static int g_d8984_trace_armed;
static uint32_t g_d8ff0_manager;
static uint32_t g_trace_sentinel;
enum {
    BOZ_PROBE_THUMB16 = 1,
    BOZ_PROBE_ARM32 = 2,
};

typedef struct {
    uint32_t off;
    uint32_t saved;
    uint8_t mode;
    int armed;
} boz_probe_t;

#define BOZ_MAX_MASS_PROBES 512u
static boz_probe_t g_tree_probes[BOZ_MAX_MASS_PROBES] = {
    {0x000da228u, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da50au, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da50cu, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da50eu, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da510u, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da52au, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da6acu, 0, BOZ_PROBE_THUMB16, 0},
    {0x000da816u, 0, BOZ_PROBE_THUMB16, 0},
    {0x000daef2u, 0, BOZ_PROBE_THUMB16, 0},
};
static unsigned g_tree_probe_count = 9u;
static int g_defer_owner_second_enabled;
static int g_compat_null_child_skip;
static int g_compat_skip_null_registration;
static volatile sig_atomic_t g_compat_null_registration_count;
#define BOZ_NULL_REGISTRATION_SKIP_MAX 32
static volatile sig_atomic_t g_compat_null_child_skip_count;
#define BOZ_NULL_CHILD_SKIP_MAX 128
static int g_handler_pairs_enabled;
static int g_defer_selector_stream_enabled;
static int g_handler_pairs_started;
static int g_handler_pair_pending;
static unsigned g_handler_pair_count;
static uint32_t g_handler_pair_target;
#define BOZ_HANDLER_PAIR_LIMIT 48u

/* One-shot probes armed only after the DB31C dispatch. This avoids
 * consuming the fallback probes on the earlier successful invocation. */
static bool is_deferred_owner_second_site(uint32_t off) {
    switch (off) {
    case 0x000d8f0eu: /* handler lookup entry */
    case 0x000d8f14u: /* after loading registry sentinel and root */
    case 0x000d8f2au: /* search completed */
    case 0x000d8f36u: /* compare selected node with sentinel */
    case 0x000d8f3au: /* handler candidate */
    case 0x000d8f40u: /* callback BLX, captured before instruction */
    case 0x000d8f42u: /* return instruction, deferred until BLX trap */
    case 0x000d8f44u: /* no match: move zero to r0 */
    case 0x000da716u:
    case 0x000da71cu:
    case 0x000da720u:
    case 0x000da728u:
    case 0x000da72cu:
    case 0x000da730u:
        return true;
    default:
        return false;
    }
}

static const char *probe_mode_name(uint8_t mode) {
    return mode == BOZ_PROBE_ARM32 ? "arm32" : "thumb16";
}

static bool probe_mode_allowed(uint32_t off, uint8_t mode) {
    if (mode == BOZ_PROBE_THUMB16) {
        /* Confirmed by runtime CPSR at D8FF0/DA6C6/DAA84/DA4DC. */
        return !(off & 1u) &&
               ((off >= 0x000d6000u && off < 0x000db800u) ||
                /* Instruction boundaries verified in the restored S3E. */
                (off >= 0x0020fe1cu && off < 0x0020fe76u));
    }
    if (mode == BOZ_PROBE_ARM32) {
        /* Confirmed ARM-state windows from the 0x254fxx and 0x34c1xx traces. */
        return !(off & 3u) &&
               ((off >= 0x00250000u && off < 0x00260000u) ||
                (off >= 0x002fd500u && off < 0x002fd580u) ||
                (off >= 0x002fe000u && off < 0x00300500u) ||
                (off >= 0x0034b000u && off < 0x0034f000u));
    }
    return false;
}

static void load_mass_probe_env(void) {
    const char *fresh = getenv("BOZ_CLEAR_DEFAULT_MASS_PROBES");
    if (fresh && strcmp(fresh, "1") == 0) {
        g_tree_probe_count = 0u;
    }
    const char *s = getenv("BOZ_MASS_PROBES");
    if (!s || !*s) {
        return;
    }
    unsigned rejected = 0;
    while (*s && g_tree_probe_count < BOZ_MAX_MASS_PROBES) {
        while (*s == ',' || *s == ' ' || *s == '\t') {
            ++s;
        }
        if (!*s) {
            break;
        }

        uint8_t mode = 0;
        if ((s[0] == 't' || s[0] == 'T') && s[1] == ':') {
            mode = BOZ_PROBE_THUMB16;
            s += 2;
        } else if ((s[0] == 'a' || s[0] == 'A') && s[1] == ':') {
            mode = BOZ_PROBE_ARM32;
            s += 2;
        }

        char *end = NULL;
        unsigned long parsed = strtoul(s, &end, 0);
        if (end == s || parsed > UINT32_MAX) {
            ++rejected;
            while (*s && *s != ',') {
                ++s;
            }
            continue;
        }
        uint32_t off = (uint32_t)parsed;

        /* Backward compatibility is intentionally narrow: an untyped offset
         * is accepted only inside the runtime-confirmed Thumb window. */
        if (!mode && !(off & 1u) && off >= 0x000d6000u && off < 0x000db800u) {
            mode = BOZ_PROBE_THUMB16;
        }

        if (!probe_mode_allowed(off, mode)) {
            ++rejected;
        } else {
            bool dup = false;
            for (unsigned i = 0; i < g_tree_probe_count; ++i) {
                if (g_tree_probes[i].off == off) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                g_tree_probes[g_tree_probe_count++] =
                    (boz_probe_t){off, 0, mode, 0};
            }
        }

        s = end;
        while (*s && *s != ',') {
            ++s;
        }
    }
    fprintf(stderr,
            "[MASS_PROBE] candidates=%u rejected=%u capacity=%u\n",
            g_tree_probe_count, rejected, BOZ_MAX_MASS_PROBES);
}

/* Re-arm only a confirmed 16-bit instruction address. The pair probes are
 * mutually exclusive: never patch BLX and its immediately following POP
 * at the same time (PC-after-breakpoint ambiguity). */
static bool arm_one_thumb_probe(uint32_t off) {
    if (!probe_mode_allowed(off, BOZ_PROBE_THUMB16)) {
        return false;
    }
    for (unsigned i = 0; i < g_tree_probe_count; ++i) {
        boz_probe_t *p = &g_tree_probes[i];
        if (p->off != off || p->mode != BOZ_PROBE_THUMB16 || p->armed) {
            continue;
        }
        uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + off);
        p->saved = *site;
        *site = 0xbe00u;
        __builtin___clear_cache((char *)site, (char *)(site + 1));
        p->armed = 1;
        return true;
    }
    return false;
}

/* Called only after the matching Thumb BLX at DB2FA: a previously
 * unseen ARM-state serializer probe cannot be consumed by an earlier
 * unrelated call to the shared wrapper. */
static bool arm_one_arm_probe(uint32_t off) {
    if (!probe_mode_allowed(off, BOZ_PROBE_ARM32)) {
        return false;
    }
    for (unsigned i = 0; i < g_tree_probe_count; ++i) {
        boz_probe_t *p = &g_tree_probes[i];
        if (p->off != off || p->mode != BOZ_PROBE_ARM32 || p->armed) {
            continue;
        }
        uint32_t *site = (uint32_t *)(uintptr_t)(g_loaded_base + off);
        p->saved = *site;
        *site = 0xe1200070u; /* ARM BKPT */
        __builtin___clear_cache((char *)site, (char *)(site + 1));
        p->armed = 1;
        return true;
    }
    return false;
}

static void arm_tree_probes(void) {
    load_mass_probe_env();
    const char *defer = getenv("BOZ_DEFER_OWNER_SECOND");
    g_defer_owner_second_enabled = defer && strcmp(defer, "1") == 0;
    const char *pairs = getenv("BOZ_TRACE_HANDLER_PAIRS");
    g_handler_pairs_enabled = g_defer_owner_second_enabled &&
                              pairs && strcmp(pairs, "1") == 0;
    const char *selector_stream = getenv("BOZ_TRACE_SELECTOR_STREAM");
    g_defer_selector_stream_enabled =
        selector_stream && strcmp(selector_stream, "1") == 0;
    unsigned armed = 0;
    for (unsigned i = 0; i < g_tree_probe_count; ++i) {
        boz_probe_t *p = &g_tree_probes[i];
        if (!probe_mode_allowed(p->off, p->mode)) {
            continue;
        }
        if ((g_defer_owner_second_enabled && is_deferred_owner_second_site(p->off)) ||
            (g_handler_pairs_enabled && p->off == 0x000d8f42u) ||
            (g_defer_selector_stream_enabled && p->off == 0x00257bd4u) ||
            (g_compat_skip_null_registration && p->off == 0x0020fe72u)) {
            continue;
        }
        if (p->mode == BOZ_PROBE_THUMB16) {
            uint16_t *site =
                (uint16_t *)(uintptr_t)(g_loaded_base + p->off);
            p->saved = *site;
            *site = 0xbe00u;
            __builtin___clear_cache((char *)site, (char *)(site + 1));
        } else {
            uint32_t *site =
                (uint32_t *)(uintptr_t)(g_loaded_base + p->off);
            p->saved = *site;
            *site = 0xe1200070u; /* ARM-state BKPT #0 */
            __builtin___clear_cache((char *)site, (char *)(site + 1));
        }
        p->armed = 1;
        ++armed;
    }
    fprintf(stderr, "[MASS_PROBE_ARMED] count=%u\n", armed);
}

static void arm_dispatch_trace(void) {
    uint32_t *site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f04u);
    g_arm_dispatch_saved = *site;
    *site = 0xe1200070u; /* ARM-state BKPT #0 */
    __builtin___clear_cache((char *)site, (char *)site + sizeof(*site));
    g_arm_dispatch_trace_armed = 1;
}

static void arm_dispatch_callsite_trace(void) {
    uint32_t *site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f40u);
    g_arm_callsite_saved = *site;
    *site = 0xe1200070u; /* ARM-state BKPT #0 */
    __builtin___clear_cache((char *)site, (char *)site + sizeof(*site));
    g_arm_callsite_trace_armed = 1;
}

static void arm_d8ff0_trace(void) {
    uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8ff0u);
    g_d8ff0_saved = *site;
    *site = 0xbe00u;
    __builtin___clear_cache((char *)site, (char *)(site + 1));
    g_d8ff0_trace_armed = 1;
}

static void arm_d8984_trace(void) {
    uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8984u);
    g_d8984_saved = *site;
    *site = 0xbe00u;
    __builtin___clear_cache((char *)site, (char *)(site + 1));
    g_d8984_trace_armed = 1;
}

static void arm_d8ffa_trace(void) {
    uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8ffau);
    g_d8ffa_saved = *site;
    *site = 0xbe00u;
    __builtin___clear_cache((char *)site, (char *)(site + 1));
    g_d8ffa_trace_armed = 1;
}

static void arm_da6c6_trace(void) {
    uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000da6c6u);
    g_da6c6_saved = *site;
    *site = 0xbe00u;
    __builtin___clear_cache((char *)site, (char *)(site + 1));
    g_da6c6_trace_armed = 1;
}
#endif

static void crash_handler(int sig, siginfo_t *info, void *context) {
#if defined(__arm__)
    ucontext_t *uc = (ucontext_t *)context;
    if ((sig == SIGTRAP || sig == SIGILL) && g_arm_return_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x00254f44u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x00254f48u)) {
        uint32_t *ret_site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f44u);
        *ret_site = g_arm_return_saved;
        __builtin___clear_cache((char *)ret_site, (char *)ret_site + sizeof(*ret_site));
        g_arm_return_trace_armed = 0;
        if (g_arm_dispatch_call_seq > 0u &&
            g_arm_dispatch_call_seq <= BOZ_ARM_ALLOC_TRACE_MAX) {
            g_arm_return_r0[g_arm_dispatch_call_seq - 1u] =
                (uint32_t)uc->uc_mcontext.arm_r0;
        }
        fprintf(stderr,
                "[ARM_DISPATCH_RETURN] seq=%u r0=%08lx r1=%08lx r2=%08lx r3=%08lx "
                "r4=%08lx r5=%08lx r6=%08lx r7=%08lx lr=%08lx cpsr=%08lx\n",
                g_arm_dispatch_call_seq,
                (unsigned long)uc->uc_mcontext.arm_r0,
                (unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2,
                (unsigned long)uc->uc_mcontext.arm_r3,
                (unsigned long)uc->uc_mcontext.arm_r4,
                (unsigned long)uc->uc_mcontext.arm_r5,
                (unsigned long)uc->uc_mcontext.arm_r6,
                (unsigned long)uc->uc_mcontext.arm_r7,
                (unsigned long)uc->uc_mcontext.arm_lr,
                (unsigned long)uc->uc_mcontext.arm_cpsr);
        if (g_arm_dispatch_call_seq < BOZ_ARM_ALLOC_TRACE_MAX) {
            uint32_t *call_site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f40u);
            g_arm_callsite_saved = *call_site;
            *call_site = 0xe1200070u;
            __builtin___clear_cache((char *)call_site, (char *)call_site + sizeof(*call_site));
            g_arm_callsite_trace_armed = 1;
        }
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x00254f44u;
        return;
    }
    if ((sig == SIGTRAP || sig == SIGILL) && g_arm_callsite_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x00254f40u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x00254f44u)) {
        uint32_t *site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f40u);
        *site = g_arm_callsite_saved;
        __builtin___clear_cache((char *)site, (char *)site + sizeof(*site));
        g_arm_callsite_trace_armed = 0;
        ++g_arm_dispatch_call_seq;
        if (g_arm_dispatch_call_seq <= BOZ_ARM_ALLOC_TRACE_MAX) {
            g_arm_call_size[g_arm_dispatch_call_seq - 1u] =
                (uint32_t)uc->uc_mcontext.arm_r2;
            g_arm_call_lr[g_arm_dispatch_call_seq - 1u] =
                (uint32_t)uc->uc_mcontext.arm_lr;
        }
        fprintf(stderr,
                "[ARM_DISPATCH_CALL] seq=%u target=%08lx object=%08lx arg1=%08lx arg2=%08lx "
                "r0=%08lx r1=%08lx r2=%08lx lr=%08lx cpsr=%08lx\n",
                g_arm_dispatch_call_seq,
                (unsigned long)uc->uc_mcontext.arm_r3,
                (unsigned long)uc->uc_mcontext.arm_r4,
                (unsigned long)uc->uc_mcontext.arm_r7,
                (unsigned long)uc->uc_mcontext.arm_r5,
                (unsigned long)uc->uc_mcontext.arm_r0,
                (unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2,
                (unsigned long)uc->uc_mcontext.arm_lr,
                (unsigned long)uc->uc_mcontext.arm_cpsr);
        if (g_arm_dispatch_call_seq <= BOZ_ARM_ALLOC_TRACE_MAX) {
            uint32_t *ret_site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f44u);
            g_arm_return_saved = *ret_site;
            *ret_site = 0xe1200070u;
            __builtin___clear_cache((char *)ret_site, (char *)ret_site + sizeof(*ret_site));
            g_arm_return_trace_armed = 1;
        }
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x00254f40u;
        return;
    }
    if ((sig == SIGTRAP || sig == SIGILL) && g_arm_dispatch_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x00254f04u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x00254f08u)) {
        uint32_t *site = (uint32_t *)(uintptr_t)(g_loaded_base + 0x00254f04u);
        *site = g_arm_dispatch_saved;
        __builtin___clear_cache((char *)site, (char *)site + sizeof(*site));
        g_arm_dispatch_trace_armed = 0;
        fprintf(stderr,
                "[ARM_DISPATCH_ENTER] r0=%08lx r1=%08lx r2=%08lx r3=%08lx "
                "r4=%08lx r5=%08lx r6=%08lx r7=%08lx r8=%08lx lr=%08lx cpsr=%08lx\n",
                (unsigned long)uc->uc_mcontext.arm_r0,
                (unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2,
                (unsigned long)uc->uc_mcontext.arm_r3,
                (unsigned long)uc->uc_mcontext.arm_r4,
                (unsigned long)uc->uc_mcontext.arm_r5,
                (unsigned long)uc->uc_mcontext.arm_r6,
                (unsigned long)uc->uc_mcontext.arm_r7,
                (unsigned long)uc->uc_mcontext.arm_r8,
                (unsigned long)uc->uc_mcontext.arm_lr,
                (unsigned long)uc->uc_mcontext.arm_cpsr);
        {
            uintptr_t lr = (uintptr_t)uc->uc_mcontext.arm_lr;
            uintptr_t image_lo = g_loaded_base;
            uintptr_t image_hi = g_loaded_base + 0x0041d970u;
            if (lr >= image_lo + 16u && lr + 16u < image_hi) {
                uint32_t *p = (uint32_t *)(lr - 16u);
                fprintf(stderr,
                        "[ARM_CALLER_WORDS] lr=%08lx "
                        "m16=%08x m12=%08x m8=%08x m4=%08x "
                        "p0=%08x p4=%08x p8=%08x p12=%08x\n",
                        (unsigned long)lr,
                        p[0], p[1], p[2], p[3],
                        p[4], p[5], p[6], p[7]);
            }
        }
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x00254f04u;
        return;
    }
    if (sig == SIGTRAP || sig == SIGILL) {
        for (unsigned i = 0; i < g_tree_probe_count; ++i) {
            boz_probe_t *p = &g_tree_probes[i];
            uint32_t step = p->mode == BOZ_PROBE_ARM32 ? 4u : 2u;
            if (p->armed &&
                (uc->uc_mcontext.arm_pc == g_loaded_base + p->off ||
                 uc->uc_mcontext.arm_pc == g_loaded_base + p->off + step)) {
                if (p->mode == BOZ_PROBE_THUMB16) {
                    uint16_t *site =
                        (uint16_t *)(uintptr_t)(g_loaded_base + p->off);
                    *site = (uint16_t)p->saved;
                    __builtin___clear_cache((char *)site, (char *)(site + 1));
                } else {
                    uint32_t *site =
                        (uint32_t *)(uintptr_t)(g_loaded_base + p->off);
                    *site = p->saved;
                    __builtin___clear_cache((char *)site, (char *)(site + 1));
                }
                p->armed = 0;
                if (p->off == 0x000db2fau && g_defer_selector_stream_enabled) {
                    g_defer_selector_stream_enabled = 0;
                    bool ok = arm_one_arm_probe(0x00257bd4u);
                    fprintf(stderr,
                            "[SELECTOR_STREAM_ARM] at=0xdb2fa ok=%d\n",
                            ok ? 1 : 0);
                }
                if (p->off == 0x0025812cu) {
                    /* Verified ARM entry: CMP r1,#1; r0 is filename,
                     * r1 selects rb(1) versus wb(other). */
                    fprintf(stderr,
                            "[SERIALIZER_FILE_OPEN] stage=entry name_ptr=%08lx "
                            "read_mode=%08lx\n",
                            (unsigned long)uc->uc_mcontext.arm_r0,
                            (unsigned long)uc->uc_mcontext.arm_r1);
                }
                if (p->off == 0x00258170u) {
                    /* Verified ARM STR r0,[r3,#8], before the store.
                     * r0 is the FILE* returned by native open helper. */
                    fprintf(stderr,
                            "[SERIALIZER_FILE_OPEN] stage=assign file=%08lx "
                            "global=%08lx\n",
                            (unsigned long)uc->uc_mcontext.arm_r0,
                            (unsigned long)uc->uc_mcontext.arm_r3);
                }
                if (p->off == 0x00257bd4u) {
                    /* ARM instruction 257BD0 has already loaded the file
                     * argument into r3. At BD4 the file register is final. */
                    fprintf(stderr,
                            "[SELECTOR_STREAM] off=257bd4 buffer=%08lx "
                            "file=%08lx global=%08lx read_flag=%08lx "
                            "element_size=%08lx count=%08lx\n",
                            (unsigned long)uc->uc_mcontext.arm_r0,
                            (unsigned long)uc->uc_mcontext.arm_r3,
                            (unsigned long)uc->uc_mcontext.arm_ip,
                            (unsigned long)uc->uc_mcontext.arm_r2,
                            (unsigned long)uc->uc_mcontext.arm_r1,
                            (unsigned long)uc->uc_mcontext.arm_r4);
                }
                if (p->off == 0x000db31cu && g_defer_owner_second_enabled) {
                    unsigned deferred_armed = 0;
                    g_defer_owner_second_enabled = 0;
                    if (g_handler_pairs_enabled) {
                        g_handler_pairs_started = 1;
                    }
                    for (unsigned j = 0; j < g_tree_probe_count; ++j) {
                        boz_probe_t *q = &g_tree_probes[j];
                        if (!is_deferred_owner_second_site(q->off) ||
                            (g_handler_pairs_enabled && q->off == 0x000d8f42u) ||
                            q->mode != BOZ_PROBE_THUMB16 || q->armed ||
                            !probe_mode_allowed(q->off, q->mode)) {
                            continue;
                        }
                        uint16_t *deferred_site =
                            (uint16_t *)(uintptr_t)(g_loaded_base + q->off);
                        q->saved = *deferred_site;
                        *deferred_site = 0xbe00u;
                        __builtin___clear_cache((char *)deferred_site,
                                                (char *)(deferred_site + 1));
                        q->armed = 1;
                        ++deferred_armed;
                    }
                    fprintf(stderr,
                            "[SECOND_OWNER_ARMED] count=%u r0=%08lx r2=%08lx r8=%08lx\n",
                            deferred_armed,
                            (unsigned long)uc->uc_mcontext.arm_r0,
                            (unsigned long)uc->uc_mcontext.arm_r2,
                            (unsigned long)uc->uc_mcontext.arm_r8);
                }
                /* One call probe arms the following return probe; the return
                 * probe then re-arms the call. Every pair belongs to one
                 * specific BLX invocation, including its actual r0 result. */
                if (g_handler_pairs_started &&
                    p->off == 0x000d8f40u &&
                    !g_handler_pair_pending &&
                    g_handler_pair_count < BOZ_HANDLER_PAIR_LIMIT) {
                    ++g_handler_pair_count;
                    g_handler_pair_target = (uint32_t)uc->uc_mcontext.arm_r2;
                    g_handler_pair_pending = arm_one_thumb_probe(0x000d8f42u);
                    fprintf(stderr,
                            "[HANDLER_PAIR_CALL] seq=%u target=%08x r0=%08lx "
                            "r1=%08lx r2=%08lx armed_return=%d\n",
                            g_handler_pair_count, g_handler_pair_target,
                            (unsigned long)uc->uc_mcontext.arm_r0,
                            (unsigned long)uc->uc_mcontext.arm_r1,
                            (unsigned long)uc->uc_mcontext.arm_r2,
                            g_handler_pair_pending);
                } else if (g_handler_pairs_started &&
                           p->off == 0x000d8f42u &&
                           g_handler_pair_pending) {
                    fprintf(stderr,
                            "[HANDLER_PAIR_RET] seq=%u target=%08x result=%08lx\n",
                            g_handler_pair_count, g_handler_pair_target,
                            (unsigned long)uc->uc_mcontext.arm_r0);
                    g_handler_pair_pending = 0;
                    if (g_handler_pair_count < BOZ_HANDLER_PAIR_LIMIT) {
                        (void)arm_one_thumb_probe(0x000d8f40u);
                    }
                }
                /*
                 * Mass probes can stop at dozens of unrelated instructions.
                 * r4/r5 are not guaranteed to be valid pointers at every site,
                 * so never dereference them from the signal handler. Raw
                 * register values are enough for offline manager correlation.
                 */
                uint32_t p4 = 0;
                uint32_t p5 = 0;
                uint32_t p3 = 0;
                if (p->off == 0x000daa84u && uc->uc_mcontext.arm_r3) {
                    g_trace_sentinel = (uint32_t)uc->uc_mcontext.arm_r3;
                    p3 = *(uint32_t *)(uintptr_t)(g_trace_sentinel + 4u);
                }
                uint32_t stack_word0 = 0;
                uint32_t stack_word28 = 0;
                /* These sites use a validated stack frame; avoid arbitrary
                 * pointer dereferences at unrelated probe addresses. */
                if (p->off == 0x000db294u ||
                    p->off == 0x000db298u ||
                    p->off == 0x000db2fau ||
                    p->off == 0x000db2feu ||
                    p->off == 0x000db306u ||
                    p->off == 0x000db31cu) {
                    const uint32_t *stack_frame =
                        (const uint32_t *)(uintptr_t)uc->uc_mcontext.arm_sp;
                    stack_word0 = stack_frame[0];
                    stack_word28 = stack_frame[7];
                }
                uint32_t sentinel_root =
                    g_trace_sentinel
                        ? *(uint32_t *)(uintptr_t)(g_trace_sentinel + 4u)
                        : 0;
                fprintf(stderr,
                        "[TREE_PROBE] mode=%s off=%06x r0=%08lx r1=%08lx r2=%08lx "
                        "r3=%08lx r3p4=%08x r4=%08lx r5=%08lx r4p4=%08x r5p4=%08x "
                        "r6=%08lx r7=%08lx r8=%08lx sentinel=%08x root=%08x lr=%08lx "
                        "sp=%08lx sp0=%08x sp28=%08x\n",
                        probe_mode_name(p->mode), p->off,
                        (unsigned long)uc->uc_mcontext.arm_r0,
                        (unsigned long)uc->uc_mcontext.arm_r1,
                        (unsigned long)uc->uc_mcontext.arm_r2,
                        (unsigned long)uc->uc_mcontext.arm_r3, p3,
                        (unsigned long)uc->uc_mcontext.arm_r4,
                        (unsigned long)uc->uc_mcontext.arm_r5, p4, p5,
                        (unsigned long)uc->uc_mcontext.arm_r6,
                        (unsigned long)uc->uc_mcontext.arm_r7,
                        (unsigned long)uc->uc_mcontext.arm_r8,
                        g_trace_sentinel, sentinel_root,
                        (unsigned long)uc->uc_mcontext.arm_lr,
                        (unsigned long)uc->uc_mcontext.arm_sp,
                        stack_word0, stack_word28);
                /* Opt-in only: skip registration of a null child,
                 * from getter 30204C via r1 at Thumb BLX 20FE6E.
                 * Trap 20FE72 re-arms the call probe so earlier valid
                 * invocations do not consume the null guard. */
                if (g_compat_skip_null_registration &&
                    (uc->uc_mcontext.arm_cpsr & 0x20u) &&
                    p->off == 0x0020fe6eu) {
                    const int null_pointer = uc->uc_mcontext.arm_r1 == 0;
                    const int may_skip = g_compat_null_registration_count <
                        BOZ_NULL_REGISTRATION_SKIP_MAX;
                    const bool followup = arm_one_thumb_probe(0x0020fe72u);
                    if (null_pointer && may_skip && followup) {
                        ++g_compat_null_registration_count;
                        fprintf(stderr,
                                "[BOZ_NULL_REGISTRATION_SKIP] n=%d "
                                "call=20fe6e r1=00000000 next=20fe72\n",
                                (int)g_compat_null_registration_count);
                        uc->uc_mcontext.arm_pc = g_loaded_base + 0x0020fe72u;
                        return;
                    }
                } else if (g_compat_skip_null_registration &&
                           p->off == 0x0020fe72u) {
                    (void)arm_one_thumb_probe(0x0020fe6eu);
                }
                uc->uc_mcontext.arm_pc = g_loaded_base + p->off;
                return;
            }
        }
    }
    if (sig == SIGTRAP && g_d8984_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x000d8984u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x000d8986u)) {
        uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8984u);
        *site = g_d8984_saved;
        __builtin___clear_cache((char *)site, (char *)(site + 1));
        g_d8984_trace_armed = 0;
        fprintf(stderr, "[MANAGER_TREE_INIT] manager=%08lx new20=%08lx new24=%08lx old20=%08x old24=%08x lr=%08lx\n",
                (unsigned long)uc->uc_mcontext.arm_r4,
                (unsigned long)uc->uc_mcontext.arm_r10,
                (unsigned long)uc->uc_mcontext.arm_r9,
                *(uint32_t *)(uintptr_t)(uc->uc_mcontext.arm_r4 + 0x20u),
                *(uint32_t *)(uintptr_t)(uc->uc_mcontext.arm_r4 + 0x24u),
                (unsigned long)uc->uc_mcontext.arm_lr);
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x000d8984u;
        return;
    }
    if (sig == SIGTRAP && g_d8ffa_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x000d8ffau ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x000d8ffcu)) {
        uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8ffau);
        *site = g_d8ffa_saved;
        __builtin___clear_cache((char *)site, (char *)(site + 1));
        g_d8ffa_trace_armed = 0;
        uint32_t manager = g_d8ff0_manager;
        uint32_t sentinel = manager ? *(uint32_t *)(uintptr_t)(manager + 0x20u) : 0;
        uint32_t root = sentinel ? *(uint32_t *)(uintptr_t)(sentinel + 4u) : 0;
        for (unsigned i = 0;
             i < g_arm_dispatch_call_seq && i < BOZ_ARM_ALLOC_TRACE_MAX;
             ++i) {
            if (g_arm_return_r0[i] == sentinel) {
                fprintf(stderr,
                        "[ARM_ALLOC_MATCH] kind=sentinel seq=%u size=%08x "
                        "caller_lr=%08x value=%08x\n",
                        i + 1u, g_arm_call_size[i], g_arm_call_lr[i],
                        g_arm_return_r0[i]);
            }
            if (root && g_arm_return_r0[i] == root) {
                fprintf(stderr,
                        "[ARM_ALLOC_MATCH] kind=root seq=%u size=%08x "
                        "caller_lr=%08x value=%08x\n",
                        i + 1u, g_arm_call_size[i], g_arm_call_lr[i],
                        g_arm_return_r0[i]);
            }
        }
        fprintf(stderr, "[D8FF0_HASH] hash=%08lx manager=%08x sentinel=%08x root=%08x",
                (unsigned long)uc->uc_mcontext.arm_r0, manager, sentinel, root);
        if (root && root != sentinel) {
            const uint32_t *node = (const uint32_t *)(uintptr_t)root;
            fprintf(stderr, " root_key=%08x root_payload=%08x left=%08x right=%08x",
                    node[4], node[5], node[2], node[3]);
        }
        fprintf(stderr, "\n");
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x000d8ffau;
        return;
    }
    if (sig == SIGTRAP && g_da6c6_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x000da6c6u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x000da6c8u)) {
        uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000da6c6u);
        *site = g_da6c6_saved;
        __builtin___clear_cache((char *)site, (char *)(site + 1));
        g_da6c6_trace_armed = 0;
        fprintf(stderr, "[DA6C6_ENTER] r0=%08lx r1=%08lx r2=%08lx r3=%08lx r4=%08lx r5=%08lx r6=%08lx r7=%08lx r8=%08lx lr=%08lx\n",
                (unsigned long)uc->uc_mcontext.arm_r0,(unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2,(unsigned long)uc->uc_mcontext.arm_r3,
                (unsigned long)uc->uc_mcontext.arm_r4,(unsigned long)uc->uc_mcontext.arm_r5,
                (unsigned long)uc->uc_mcontext.arm_r6,(unsigned long)uc->uc_mcontext.arm_r7,
                (unsigned long)uc->uc_mcontext.arm_r8,(unsigned long)uc->uc_mcontext.arm_lr);
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x000da6c6u;
        return;
    }
    if (sig == SIGTRAP && g_d8ff0_trace_armed &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x000d8ff0u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x000d8ff2u)) {
        uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8ff0u);
        *site = g_d8ff0_saved;
        __builtin___clear_cache((char *)site, (char *)(site + 1));
        g_d8ff0_trace_armed = 0;
        g_d8ff0_manager = (uint32_t)uc->uc_mcontext.arm_r0;
        for (unsigned i = 0;
             i < g_arm_dispatch_call_seq && i < BOZ_ARM_ALLOC_TRACE_MAX;
             ++i) {
            if (g_arm_return_r0[i] == g_d8ff0_manager) {
                fprintf(stderr,
                        "[ARM_ALLOC_MATCH] kind=manager seq=%u size=%08x "
                        "caller_lr=%08x value=%08x\n",
                        i + 1u, g_arm_call_size[i], g_arm_call_lr[i],
                        g_arm_return_r0[i]);
            }
        }
        arm_d8ffa_trace();
        fprintf(stderr, "[D8FF0_ENTER] manager=%08lx key=%08lx r2=%08lx r3=%08lx lr=%08lx cpsr=%08lx",
                (unsigned long)uc->uc_mcontext.arm_r0, (unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2, (unsigned long)uc->uc_mcontext.arm_r3,
                (unsigned long)uc->uc_mcontext.arm_lr, (unsigned long)uc->uc_mcontext.arm_cpsr);
        if (uc->uc_mcontext.arm_r1) {
            const unsigned char *s = (const unsigned char *)(uintptr_t)uc->uc_mcontext.arm_r1;
            fprintf(stderr, " key_bytes=");
            for (int i = 0; i < 64; ++i) {
                unsigned char ch = s[i];
                if (!ch) break;
                fputc((ch >= 32 && ch < 127) ? ch : '.', stderr);
            }
        }
        fprintf(stderr, "\n");
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x000d8ff0u;
        return;
    }
    /*
     * Opt-in diagnostic A/B only. If the missing child pointer reaches the
     * *verified* ARM LDRH r3,[r4,#44], do not synthesize an object. Instead
     * run the routine's own temporary-object cleanup (MOV r0,r6 at 2FE0F8
     * followed by its destructor and normal epilogue). This is NOT a
     * gameplay fix: it tests whether the missing optional child alone is
     * preventing further boot progress. The unmodified run remains default.
     */
    if (sig == SIGSEGV && g_compat_null_child_skip &&
        uc->uc_mcontext.arm_pc == g_loaded_base + 0x002fe0a8u &&
        uc->uc_mcontext.arm_r4 == 0 &&
        (uc->uc_mcontext.arm_cpsr & 0x20u) == 0 &&
        g_compat_null_child_skip_count < BOZ_NULL_CHILD_SKIP_MAX) {
        ++g_compat_null_child_skip_count;
        fprintf(stderr,
                "[BOZ_NULL_CHILD_SKIP] n=%d pc=2fe0a8 r4=%08lx "
                "cleanup_pc=2fe0f8 lr=%08lx\n",
                (int)g_compat_null_child_skip_count,
                (unsigned long)uc->uc_mcontext.arm_r4,
                (unsigned long)uc->uc_mcontext.arm_lr);
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x002fe0f8u;
        return;
    }
    if (sig == SIGSEGV && recover_bucket_allocator_fault(uc)) return;
    if (sig == SIGSEGV && recover_null_buffer_write(uc)) return;
    if (sig == SIGSEGV && recover_null_buffer_slot(uc)) return;
    /* Observe the missing host object; do not fabricate control flow. */
    if (sig == SIGSEGV && uc->uc_mcontext.arm_pc == g_loaded_base + 0x0db31eu &&
        uc->uc_mcontext.arm_r0 == 0) {
        fprintf(stderr, "[NULL_OBJECT] BOZ+0x0db31e after BLX r12; "
                        "lr=0x%08lx r12=0x%08lx sp=0x%08lx\n",
                (unsigned long)uc->uc_mcontext.arm_lr,
                (unsigned long)uc->uc_mcontext.arm_ip,
                (unsigned long)uc->uc_mcontext.arm_sp);
        fprintf(stderr,
                "[NULL_FLOW] r0=%08lx r1=%08lx r2=%08lx r3=%08lx "
                "r4=%08lx r5=%08lx r6=%08lx r7=%08lx r8=%08lx r9=%08lx "
                "r10=%08lx fp=%08lx ip=%08lx lr=%08lx\n",
                (unsigned long)uc->uc_mcontext.arm_r0, (unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2, (unsigned long)uc->uc_mcontext.arm_r3,
                (unsigned long)uc->uc_mcontext.arm_r4, (unsigned long)uc->uc_mcontext.arm_r5,
                (unsigned long)uc->uc_mcontext.arm_r6, (unsigned long)uc->uc_mcontext.arm_r7,
                (unsigned long)uc->uc_mcontext.arm_r8, (unsigned long)uc->uc_mcontext.arm_r9,
                (unsigned long)uc->uc_mcontext.arm_r10, (unsigned long)uc->uc_mcontext.arm_fp,
                (unsigned long)uc->uc_mcontext.arm_ip, (unsigned long)uc->uc_mcontext.arm_lr);
        {
            const uint32_t *spw = (const uint32_t *)(uintptr_t)uc->uc_mcontext.arm_sp;
            fprintf(stderr, "[NULL_STACK]");
            for (int n = 0; n < 24; ++n) fprintf(stderr, " %02x:%08x", n * 4, spw[n]);
            fprintf(stderr, "\n");
            const uint32_t *owner = (const uint32_t *)(uintptr_t)uc->uc_mcontext.arm_r4;
            if (owner) {
                fprintf(stderr, "[NULL_OWNER]");
                for (int n = 0; n < 40; ++n) fprintf(stderr, " %02x:%08x", n * 4, owner[n]);
                fprintf(stderr, "\n");
            }
        }
    }
    if (sig == SIGSEGV && uc->uc_mcontext.arm_pc == g_loaded_base + 0x368ddcu &&
        uc->uc_mcontext.arm_r1 == 0) {
        uc->uc_mcontext.arm_r1 = (unsigned long)(uintptr_t)g_empty_string;
        return;
    }
    if (sig == SIGSEGV && uc->uc_mcontext.arm_pc == g_loaded_base + 0x368d2cu &&
        uc->uc_mcontext.arm_r1 == 0) {
        uc->uc_mcontext.arm_r1 = (unsigned long)(uintptr_t)g_empty_string;
        return;
    }
    if (sig == SIGSEGV &&
        (uc->uc_mcontext.arm_pc == g_loaded_base + 0x24ba00u ||
         uc->uc_mcontext.arm_pc == g_loaded_base + 0x24ba30u) &&
        uc->uc_mcontext.arm_r0 == 0) {
        uc->uc_mcontext.arm_r0 = (unsigned long)(uintptr_t)g_empty_string;
        return;
    }
    if (sig == SIGSEGV && uc->uc_mcontext.arm_pc == g_loaded_base + 0x368fa4u &&
        uc->uc_mcontext.arm_r1 == 0) {
        uc->uc_mcontext.arm_r0 = 0;
        uc->uc_mcontext.arm_r2 = 0;
        uc->uc_mcontext.arm_pc = g_loaded_base + 0x369024u;
        return;
    }

    /*
     * Fault-proven provenance for BOZ+2FE7D0 (STR r1,[r0,#0x90]).
     * 301ECC saves {r3,r4,r5,lr} and calls 2FE7D0 from 301F00.
     * At the fault, the callee has no prologue: the saved LR lives at
     * [sp+12]. This classifies the *crashing invocation*, unlike BKPTs
     * which may have sampled an earlier successful one.
     * 3064FC calls 301ECC with original r1; 30AE10 calls it with r4
     * after r4 was dereferenced successfully at 30ADF4.
     */
    if (sig == SIGSEGV &&
        uc->uc_mcontext.arm_pc == g_loaded_base + 0x002fe7d0u &&
        uc->uc_mcontext.arm_r0 == 0 &&
        (uc->uc_mcontext.arm_cpsr & 0x20u) == 0 &&
        uc->uc_mcontext.arm_lr == g_loaded_base + 0x00301f04u) {
        const uint32_t *caller_stack =
            (const uint32_t *)(uintptr_t)uc->uc_mcontext.arm_sp;
        uint32_t constructor_parent_lr = caller_stack[3];
        const char *parent_class = "unknown";
        if (constructor_parent_lr == (uint32_t)(g_loaded_base + 0x00306500u)) {
            parent_class = "3064d8_r1_unchecked";
        } else if (constructor_parent_lr ==
                   (uint32_t)(g_loaded_base + 0x0030ae14u)) {
            parent_class = "30adc8_r4_prevalidated";
        }
        fprintf(stderr,
                "[BOZ_NULL_PROPERTY_ORIGIN] pc=2fe7d0 "
                "constructor=301ecc parent_lr=%08x "
                "path=%s constructor_r5=%08lx target_r4=%08lx "
                "stack_r5_saved=%08x\n",
                constructor_parent_lr, parent_class,
                (unsigned long)uc->uc_mcontext.arm_r5,
                (unsigned long)uc->uc_mcontext.arm_r4,
                caller_stack[2]);
    }
    uintptr_t crash_pc = (uintptr_t)uc->uc_mcontext.arm_pc;
    uintptr_t crash_lr = (uintptr_t)uc->uc_mcontext.arm_lr;
    uintptr_t pc_offset = crash_pc >= g_loaded_base ? crash_pc - g_loaded_base : UINTPTR_MAX;
    uintptr_t lr_code = crash_lr & ~(uintptr_t)1u;
    uintptr_t lr_offset = lr_code >= g_loaded_base ? lr_code - g_loaded_base : UINTPTR_MAX;
    unsigned char *pc_bytes = (unsigned char *)(crash_pc & ~(uintptr_t)1u);
    fprintf(stderr,
            "signal %d addr=%p pc=0x%08lx pc_off=0x%08lx lr=0x%08lx lr_off=0x%08lx "
            "sp=0x%08lx cpsr=0x%08lx thumb=%lu r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx "
            "r4=0x%08lx r5=0x%08lx r6=0x%08lx r7=0x%08lx r8=0x%08lx r9=0x%08lx "
            "r10=0x%08lx fp=0x%08lx ip=0x%08lx\n",
            sig, info ? info->si_addr : NULL, (unsigned long)crash_pc,
            (unsigned long)pc_offset, (unsigned long)crash_lr, (unsigned long)lr_offset,
            (unsigned long)uc->uc_mcontext.arm_sp, (unsigned long)uc->uc_mcontext.arm_cpsr,
            (unsigned long)((uc->uc_mcontext.arm_cpsr >> 5) & 1u),
            (unsigned long)uc->uc_mcontext.arm_r0, (unsigned long)uc->uc_mcontext.arm_r1,
            (unsigned long)uc->uc_mcontext.arm_r2, (unsigned long)uc->uc_mcontext.arm_r3,
            (unsigned long)uc->uc_mcontext.arm_r4, (unsigned long)uc->uc_mcontext.arm_r5,
            (unsigned long)uc->uc_mcontext.arm_r6, (unsigned long)uc->uc_mcontext.arm_r7,
            (unsigned long)uc->uc_mcontext.arm_r8, (unsigned long)uc->uc_mcontext.arm_r9,
            (unsigned long)uc->uc_mcontext.arm_r10, (unsigned long)uc->uc_mcontext.arm_fp,
            (unsigned long)uc->uc_mcontext.arm_ip);
    if (pc_offset != UINTPTR_MAX && pc_offset >= 8 && pc_offset + 16 < 0x41d970u) {
        fprintf(stderr, "pc-bytes:");
        for (int i = -8; i < 16; ++i) fprintf(stderr, " %02x", pc_bytes[i]);
        fprintf(stderr, "\n");
    }
    uint32_t *sp = (uint32_t *)(uintptr_t)uc->uc_mcontext.arm_sp;
    fprintf(stderr, "stack:");
    for (int i = 0; i < 32; ++i) fprintf(stderr, " %08x", sp[i]);
    fprintf(stderr, "\n");
#else
    (void)info;
    (void)context;
    fprintf(stderr, "signal %d (host architecture crash)\n", sig);
#endif
    _Exit(128 + sig);
}

static void install_crash_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

static void terminate_handler(int sig) {
    (void)sig;
    _Exit(0);
}

static void install_terminate_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = terminate_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}

int main(int argc, char **argv) {
    bool run = false;
    bool diagnostic_skip_frame_interpolation = false;
    const char *root = NULL;
    const char *image_path = NULL;
    uint32_t display_width = 640;
    uint32_t display_height = 480;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--run") == 0) {
            run = true;
        } else if (strcmp(argv[i], "--diagnostic-skip-frame-interpolation") == 0) {
            diagnostic_skip_frame_interpolation = true;
        } else if (strcmp(argv[i], "--root") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            root = argv[++i];
        } else if (strcmp(argv[i], "--display-size") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            if (!parse_display_size(argv[++i], &display_width, &display_height)) {
                fprintf(stderr, "invalid display size: %s\n", argv[i]);
                return 2;
            }
        } else if (argv[i][0] == '-') {
            usage(argv[0]);
            return 2;
        } else if (!image_path) {
            image_path = argv[i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!image_path) {
        usage(argv[0]);
        return 2;
    }

    if (!s3e_host_set_display_size(display_width, display_height)) {
        fprintf(stderr, "unable to allocate display surface: %ux%u\n", display_width,
                display_height);
        return 1;
    }

    install_crash_handlers();
    install_terminate_handlers();

    struct s3e_image image;
    if (!s3e_image_load(image_path, &image)) {
        return 1;
    }
    if (!s3e_image_parse_symbols(&image)) {
        s3e_image_free(&image);
        return 1;
    }

    fprintf(stderr, "S3E version=0x%x arch=0x%x symbols=%zu code=0x%x mem=0x%x\n",
            image.header.version, image.header.arch, image.symbols.count,
            image.header.code_file_size, image.header.code_mem_size);

    if (!s3e_host_init(root)) {
        s3e_image_free(&image);
        return 1;
    }
    s3e_host_set_config(image.file_data + image.header.config_offset, image.header.config_size);

    struct s3e_loaded_image loaded;
    if (!s3e_image_map_and_relocate(&image, s3e_host_resolve, &loaded)) {
        s3e_host_shutdown();
        s3e_image_free(&image);
        return 1;
    }
    if (diagnostic_skip_frame_interpolation) {
        fprintf(stderr,
                "[DIAGNOSTIC] frame interpolation hook skipped; this run is for host diagnostics\n");
    } else if (!codboz_install_frame_interpolation(&loaded)) {
        fprintf(stderr, "unsupported game executable: unable to install frame interpolation\n");
        s3e_loaded_image_unmap(&loaded);
        s3e_host_shutdown();
        s3e_image_free(&image);
        return 1;
    }

    uintptr_t player_name_address = (uintptr_t)s3e_host_player_name();
    if (player_name_address > UINT32_MAX ||
        !codboz_override_player_name(&loaded, (uint32_t)player_name_address)) {
        fprintf(stderr, "unable to apply configured player name\n");
    }

    fprintf(stderr, "mapped S3E at %p, entry=%p\n", (void *)loaded.base,
            (void *)(loaded.base + loaded.entry_offset));
#if defined(__arm__)
    {
        const uint32_t probes[] = {0x000da680u, 0x000da6acu, 0x000db300u, 0x000db31eu, 0x00254f20u, 0x00255e60u};
        for (size_t p = 0; p < sizeof(probes) / sizeof(probes[0]); ++p) {
            const unsigned char *q = loaded.base + probes[p];
            fprintf(stderr, "[CODE_DUMP] +0x%08x:", probes[p]);
            for (int j = 0; j < 64; ++j) fprintf(stderr, " %02x", q[j]);
            fprintf(stderr, "\n");
        }
        {
            FILE *fp = fopen("/tmp/boz-mapped-da680.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x000da680u, 1, 0x180, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-da680.bin base=0x000da680 size=0x180\n");
            }
            fp = fopen("/tmp/boz-mapped-d6000.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x000d6000u, 1, 0x5800, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-d6000.bin base=0x000d6000 size=0x5800\n");
            }
            fp = fopen("/tmp/boz-mapped-d8e80.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x000d8800u, 1, 0x3000, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-d8e80.bin base=0x000d8800 size=0x3000\\n");
            }
            fp = fopen("/tmp/boz-mapped-db2e0.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x000db2e0u, 1, 0x120, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-db2e0.bin base=0x000db2e0 size=0x120\n");
            }
            fp = fopen("/tmp/boz-mapped-254e80.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x00254e80u, 1, 0x300, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-254e80.bin base=0x00254e80 size=0x300\n");
            }
            fp = fopen("/tmp/boz-mapped-arm25.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x00250000u, 1, 0x10000, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-arm25.bin base=0x00250000 size=0x10000\n");
            }
            fp = fopen("/tmp/boz-mapped-arm34.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x0034b000u, 1, 0x4000, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-arm34.bin base=0x0034b000 size=0x4000\n");
            }
        }
    }
#endif
#if defined(__arm__)
    g_loaded_base = (uintptr_t)loaded.base;
    const char *null_child_flag = getenv("BOZ_COMPAT_NULL_CHILD_SKIP");
    g_compat_null_child_skip =
        null_child_flag && strcmp(null_child_flag, "1") == 0;
    const char *null_registration_flag = getenv("BOZ_COMPAT_SKIP_NULL_REGISTRATION");
    g_compat_skip_null_registration = null_registration_flag &&
                                    strcmp(null_registration_flag, "1") == 0;
    if (g_compat_skip_null_registration) {
        fprintf(stderr, "[BOZ_COMPAT] experimental null-registration bypass enabled\n");
    }
    if (g_compat_null_child_skip) {
        fprintf(stderr, "[BOZ_COMPAT] experimental null-child cleanup skip enabled\n");
    }
    if (getenv("BOZ_NULL_OBJECT_TRACE")) {
        arm_d8ff0_trace();
        arm_da6c6_trace();
        arm_d8984_trace();
        if (getenv("BOZ_ARM_DISPATCH_TRACE")) {
            arm_dispatch_trace();
            arm_dispatch_callsite_trace();
        }
        arm_tree_probes();
    }
#endif
    if (run) {
        int (*entry)(void) = (int (*)(void))(uintptr_t)(loaded.base + loaded.entry_offset);
        int rc = entry();
        fprintf(stderr, "S3E entry returned %d\n", rc);
    }

    s3e_loaded_image_unmap(&loaded);
    s3e_host_shutdown();
    s3e_image_free(&image);
    return 0;
}
