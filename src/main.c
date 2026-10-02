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
static int g_d8ff0_trace_armed;
static int g_da6c6_trace_armed;
static int g_d8ffa_trace_armed;
static uint32_t g_d8ff0_manager;

static void arm_d8ff0_trace(void) {
    uint16_t *site = (uint16_t *)(uintptr_t)(g_loaded_base + 0x000d8ff0u);
    g_d8ff0_saved = *site;
    *site = 0xbe00u;
    __builtin___clear_cache((char *)site, (char *)(site + 1));
    g_d8ff0_trace_armed = 1;
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
        arm_d8ffa_trace();
        fprintf(stderr, "[D8FF0_ENTER] manager=%08lx key=%08lx r2=%08lx r3=%08lx",
                (unsigned long)uc->uc_mcontext.arm_r0, (unsigned long)uc->uc_mcontext.arm_r1,
                (unsigned long)uc->uc_mcontext.arm_r2, (unsigned long)uc->uc_mcontext.arm_r3);
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

    uintptr_t crash_pc = (uintptr_t)uc->uc_mcontext.arm_pc;
    uintptr_t crash_lr = (uintptr_t)uc->uc_mcontext.arm_lr;
    uintptr_t pc_offset = crash_pc >= g_loaded_base ? crash_pc - g_loaded_base : UINTPTR_MAX;
    uintptr_t lr_code = crash_lr & ~(uintptr_t)1u;
    uintptr_t lr_offset = lr_code >= g_loaded_base ? lr_code - g_loaded_base : UINTPTR_MAX;
    unsigned char *pc_bytes = (unsigned char *)(crash_pc & ~(uintptr_t)1u);
    fprintf(stderr,
            "signal %d addr=%p pc=0x%08lx pc_off=0x%08lx lr=0x%08lx lr_off=0x%08lx "
            "sp=0x%08lx cpsr=0x%08lx thumb=%lu r0=0x%08lx r1=0x%08lx r2=0x%08lx r3=0x%08lx\n",
            sig, info ? info->si_addr : NULL, (unsigned long)crash_pc,
            (unsigned long)pc_offset, (unsigned long)crash_lr, (unsigned long)lr_offset,
            (unsigned long)uc->uc_mcontext.arm_sp, (unsigned long)uc->uc_mcontext.arm_cpsr,
            (unsigned long)((uc->uc_mcontext.arm_cpsr >> 5) & 1u),
            (unsigned long)uc->uc_mcontext.arm_r0, (unsigned long)uc->uc_mcontext.arm_r1,
            (unsigned long)uc->uc_mcontext.arm_r2, (unsigned long)uc->uc_mcontext.arm_r3);
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
        const uint32_t probes[] = {0x000da680u, 0x000da6acu, 0x000db300u, 0x000db31eu, 0x00255e60u};
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
            fp = fopen("/tmp/boz-mapped-d8e80.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x000d8e80u, 1, 0x800, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-d8e80.bin base=0x000d8e80 size=0x800\\n");
            }
            fp = fopen("/tmp/boz-mapped-db2e0.bin", "wb");
            if (fp) {
                fwrite(loaded.base + 0x000db2e0u, 1, 0x120, fp);
                fclose(fp);
                fprintf(stderr, "[MAPPED_DUMP] /tmp/boz-mapped-db2e0.bin base=0x000db2e0 size=0x120\n");
            }
        }
    }
#endif
#if defined(__arm__)
    g_loaded_base = (uintptr_t)loaded.base;
    if (getenv("BOZ_NULL_OBJECT_TRACE")) {
        arm_d8ff0_trace();
        arm_da6c6_trace();
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
