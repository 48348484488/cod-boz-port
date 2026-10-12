#include "s3e_host_internal.h"

#define GL_WRAP_FLOAT1(name, t1)                                                                   \
    static S3E_SOFTFP void host_##name(t1 a) {                                                     \
        void (*real)(t1) = lookup_gl(#name);                                                       \
        if (real)                                                                                  \
            real(a);                                                                               \
    }
#define GL_WRAP_FLOAT2(name, t1, t2)                                                               \
    static S3E_SOFTFP void host_##name(t1 a, t2 b) {                                               \
        void (*real)(t1, t2) = lookup_gl(#name);                                                   \
        if (real)                                                                                  \
            real(a, b);                                                                            \
    }
#define GL_WRAP_FLOAT3(name, t1, t2, t3)                                                           \
    static S3E_SOFTFP void host_##name(t1 a, t2 b, t3 c) {                                         \
        void (*real)(t1, t2, t3) = lookup_gl(#name);                                               \
        if (real)                                                                                  \
            real(a, b, c);                                                                         \
    }
#define GL_WRAP_FLOAT4(name, t1, t2, t3, t4)                                                       \
    static S3E_SOFTFP void host_##name(t1 a, t2 b, t3 c, t4 d) {                                   \
        void (*real)(t1, t2, t3, t4) = lookup_gl(#name);                                           \
        if (real)                                                                                  \
            real(a, b, c, d);                                                                      \
    }
#define GL_WRAP_FLOAT5(name, t1, t2, t3, t4, t5)                                                   \
    static S3E_SOFTFP void host_##name(t1 a, t2 b, t3 c, t4 d, t5 e) {                             \
        void (*real)(t1, t2, t3, t4, t5) = lookup_gl(#name);                                       \
        if (real)                                                                                  \
            real(a, b, c, d, e);                                                                   \
    }
#define GL_WRAP_FLOAT6(name, t1, t2, t3, t4, t5, t6)                                               \
    static S3E_SOFTFP void host_##name(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f) {                       \
        void (*real)(t1, t2, t3, t4, t5, t6) = lookup_gl(#name);                                   \
        if (real)                                                                                  \
            real(a, b, c, d, e, f);                                                                \
    }
#define GL_WRAP_FLOAT1_ALIAS(name, fallback, t1)                                                   \
    static S3E_SOFTFP void host_##name(t1 a) {                                                     \
        void (*real)(t1) = lookup_gl(#name);                                                       \
        if (!real)                                                                                 \
            real = lookup_gl(#fallback);                                                           \
        if (real)                                                                                  \
            real(a);                                                                               \
    }
#define GL_WRAP_FLOAT2_ALIAS(name, fallback, t1, t2)                                               \
    static S3E_SOFTFP void host_##name(t1 a, t2 b) {                                               \
        void (*real)(t1, t2) = lookup_gl(#name);                                                   \
        if (!real)                                                                                 \
            real = lookup_gl(#fallback);                                                           \
        if (real)                                                                                  \
            real(a, b);                                                                            \
    }
#define GL_WRAP_FLOAT6_ALIAS(name, fallback, t1, t2, t3, t4, t5, t6)                               \
    static S3E_SOFTFP void host_##name(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f) {                       \
        void (*real)(t1, t2, t3, t4, t5, t6) = lookup_gl(#name);                                   \
        if (!real)                                                                                 \
            real = lookup_gl(#fallback);                                                           \
        if (real)                                                                                  \
            real(a, b, c, d, e, f);                                                                \
    }

enum {
    FRAME_INTERVAL_US = 16667,
    FRAME_RESET_US = FRAME_INTERVAL_US * 4,
    REFERENCE_SURFACE_WIDTH = 640,
    REFERENCE_SURFACE_HEIGHT = 480,
    GL_VIEWPORT_VALUE = 0x0ba2,
    GL_COLOR_WRITEMASK_VALUE = 0x0c23,
    GL_FRAMEBUFFER_VALUE = 0x8d40,
};

static GLuint g_bound_framebuffer;
static unsigned g_boz_gl_clear_count;
static unsigned g_boz_gl_draw_arrays_count;
static unsigned g_boz_gl_draw_elements_count;
static unsigned g_boz_gl_draw_command_count;
static unsigned char g_boz_array_program_sampled[256];
static unsigned g_boz_array_ab_logged_swap;
static unsigned g_boz_gl_draw_tex_count;
static unsigned g_boz_gl_program_creates;
static unsigned g_boz_gl_program_links;
static unsigned g_boz_gl_program_uses;
static GLuint g_boz_last_program;
static unsigned g_boz_visual_probe_next_swap = 1u;
static unsigned g_boz_visual_probe_logged_swap;

static bool boz_visual_probe_enabled(void) {
    const char *flag = getenv("BOZ_GL_VISUAL_AB_PROBE");
    return flag && strcmp(flag, "1") == 0;
}

/* Opt-in diagnostic only. Compare removing late fullscreen image 379,
 * framing image 380, and both against normal frame 300/320. Texture IDs
 * are deliberately anchored to this verified QEMU resource sequence. */
static bool boz_layer_probe_enabled(void) {
    const char *flag = getenv("BOZ_GL_LAYER_AB_PROBE");
    return flag && strcmp(flag, "1") == 0;
}

/* Read-only, opt-in texture provenance; no texture pixels are persisted. */
enum { BOZ_TEX_SLOTS = 512, BOZ_TEX_UNITS = 16 };
struct boz_tex_meta {
    GLuint id;
    GLsizei width, height;
    unsigned uploads;
    unsigned long long sample_hash;
    unsigned char first_rgba[16];
    unsigned first_bytes;
    unsigned compressed;
    unsigned drawn;
};
static GLuint g_boz_tex_bound[BOZ_TEX_UNITS];
static GLenum g_boz_tex_active = 0x84c0u; /* GL_TEXTURE0 */
static struct boz_tex_meta g_boz_tex_meta[BOZ_TEX_SLOTS];
static unsigned g_boz_tex_meta_count;
static unsigned g_boz_tex_uploads;
static unsigned g_boz_tex_size_2x2;
static unsigned g_boz_tex_size_large;
static unsigned g_boz_tex_size_other;
static unsigned g_boz_tex_sub_uploads;
static unsigned g_boz_tex_compressed_uploads;
static unsigned g_boz_tex_compressed_unresolved;
static GLsizei g_boz_tex_max_width;
static GLsizei g_boz_tex_max_height;
static unsigned g_boz_tex_large_printed;
static unsigned g_boz_unit0_bind_changes;
static unsigned g_boz_large_texture_callers;
static unsigned g_boz_small_texture_callers;

static bool boz_texture_diag_enabled(void) {
    const char *flag = getenv("BOZ_GL_TEX_PROVENANCE");
    return flag && strcmp(flag, "1") == 0;
}

static S3E_SOFTFP void host_glActiveTexture(GLenum texture) {
    void (*real)(GLenum) = lookup_gl("glActiveTexture");
    if (real) real(texture);
    if (real && texture >= 0x84c0u && texture < 0x84c0u + BOZ_TEX_UNITS)
        g_boz_tex_active = texture;
}

static S3E_SOFTFP void host_glBindTexture(GLenum target, GLuint texture) {
    void (*real)(GLenum, GLuint) = lookup_gl("glBindTexture");
    if (real) real(target, texture);
    if (real && target == 0x0de1u && g_boz_tex_active >= 0x84c0u &&
        g_boz_tex_active < 0x84c0u + BOZ_TEX_UNITS) {
        unsigned unit = (unsigned)(g_boz_tex_active - 0x84c0u);
        GLuint previous = g_boz_tex_bound[unit];
        g_boz_tex_bound[unit] = texture;
        if (boz_texture_diag_enabled() && unit == 0u && previous != texture) {
            ++g_boz_unit0_bind_changes;
            if (g_boz_unit0_bind_changes <= 20u ||
                g_boz_unit0_bind_changes % 32u == 0u)
                fprintf(stderr,
                        "[BOZ_GL_UNIT0_BIND] seq=%u draw=%u old=%u tex=%u caller=%08lx\n",
                        g_boz_unit0_bind_changes, g_boz_gl_draw_elements_count,
                        previous, texture,
                        (unsigned long)(uintptr_t)__builtin_return_address(0));
        }
        if (boz_texture_diag_enabled() && g_boz_gl_draw_elements_count < 1u)
            fprintf(stderr, "[BOZ_GL_TEXTURE_BIND] unit=%u texture=%u\n", unit, texture);
    }
}

static struct boz_tex_meta *boz_find_tex(GLuint texture, bool create) {
    if (!texture) return NULL;
    for (unsigned i = 0; i < g_boz_tex_meta_count; ++i)
        if (g_boz_tex_meta[i].id == texture) return &g_boz_tex_meta[i];
    if (!create || g_boz_tex_meta_count >= BOZ_TEX_SLOTS) return NULL;
    struct boz_tex_meta *meta = &g_boz_tex_meta[g_boz_tex_meta_count++];
    memset(meta, 0, sizeof(*meta));
    meta->id = texture;
    return meta;
}


/* Track every actual guest draw independently of the bounded sampled log.
 * Only GL metadata is counted. No texture pixel bytes are persisted. */
static unsigned g_boz_census_total_draws;
static unsigned g_boz_census_total_2x2;
static unsigned g_boz_census_total_large;
static unsigned g_boz_census_total_unknown;
static unsigned g_boz_census_frame_draws;
static unsigned g_boz_census_frame_2x2;
static unsigned g_boz_census_frame_large;
static unsigned g_boz_census_frame_unknown;
static GLuint g_boz_census_last_tex;

static void boz_census_draw(void) {
    if (!boz_texture_diag_enabled()) return;
    GLuint texture = g_boz_tex_bound[0];
    struct boz_tex_meta *meta = boz_find_tex(texture, false);
    ++g_boz_census_total_draws;
    ++g_boz_census_frame_draws;
    g_boz_census_last_tex = texture;
    if (meta) ++meta->drawn;
    if (meta && meta->width == 2 && meta->height == 2) {
        ++g_boz_census_total_2x2;
        ++g_boz_census_frame_2x2;
    } else if (meta && (meta->width > 2 || meta->height > 2)) {
        ++g_boz_census_total_large;
        ++g_boz_census_frame_large;
    } else {
        ++g_boz_census_total_unknown;
        ++g_boz_census_frame_unknown;
    }
}

static void boz_census_swap(unsigned swap) {
    if (!boz_texture_diag_enabled()) return;
    if (swap == 1u || swap == 5u || swap == 60u || swap == 100u ||
        swap == 125u || swap == 130u || swap == 140u || swap == 150u ||
        swap == 175u || swap == 200u || swap == 225u ||
        swap == 250u || swap == 275u || swap == 300u ||
        swap == 325u) {
        unsigned large_known = 0;
        unsigned large_drawn = 0;
        for (unsigned i = 0; i < g_boz_tex_meta_count; ++i) {
            const struct boz_tex_meta *meta = &g_boz_tex_meta[i];
            if (meta->width > 2 || meta->height > 2) {
                ++large_known;
                if (meta->drawn) ++large_drawn;
            }
        }
        struct boz_tex_meta *last = boz_find_tex(g_boz_census_last_tex, false);
        fprintf(stderr,
                "[BOZ_GL_DRAW_CENSUS] swap=%u frame_draws=%u frame_2x2=%u "
                "frame_large=%u frame_unknown=%u total_draws=%u total_2x2=%u "
                "total_large=%u total_unknown=%u large_known=%u large_drawn=%u "
                "last_tex=%u last_size=%dx%d\n",
                swap, g_boz_census_frame_draws, g_boz_census_frame_2x2,
                g_boz_census_frame_large, g_boz_census_frame_unknown,
                g_boz_census_total_draws, g_boz_census_total_2x2,
                g_boz_census_total_large, g_boz_census_total_unknown,
                large_known, large_drawn, g_boz_census_last_tex,
                last ? (int)last->width : 0, last ? (int)last->height : 0);
    }
    g_boz_census_frame_draws = 0;
    g_boz_census_frame_2x2 = 0;
    g_boz_census_frame_large = 0;
    g_boz_census_frame_unknown = 0;
}

static bool boz_shader_diag_enabled(void) {
    const char *value = getenv("BOZ_GL_SHADER_DIAGNOSTIC");
    return value && strcmp(value, "1") == 0;
}

static S3E_SOFTFP GLuint host_glCreateProgram(void) {
    GLuint (*real)(void) = lookup_gl("glCreateProgram");
    GLuint program = real ? real() : 0;
    ++g_boz_gl_program_creates;
    if (boz_shader_diag_enabled() && g_boz_gl_program_creates <= 24u)
        fprintf(stderr, "[BOZ_GL_PROGRAM_CREATE] seq=%u program=%u resolved=%d\n",
                g_boz_gl_program_creates, program, real != NULL);
    return program;
}

static S3E_SOFTFP void host_glLinkProgram(GLuint program) {
    void (*real)(GLuint) = lookup_gl("glLinkProgram");
    if (real) real(program);
    ++g_boz_gl_program_links;
    if (boz_shader_diag_enabled() && g_boz_gl_program_links <= 24u) {
        GLint linked = -1;
        void (*get_program_iv)(GLuint, GLenum, GLint *) = lookup_gl("glGetProgramiv");
        if (get_program_iv) get_program_iv(program, 0x8b82u, &linked);
        fprintf(stderr, "[BOZ_GL_PROGRAM_LINK] seq=%u program=%u linked=%d resolved=%d\n",
                g_boz_gl_program_links, program, linked, real != NULL);
        if (linked == 0) {
            void (*get_log)(GLuint, GLsizei, GLsizei *, char *) = lookup_gl("glGetProgramInfoLog");
            if (get_log) {
                char info[256] = {0};
                GLsizei length = 0;
                get_log(program, 255, &length, info);
                fprintf(stderr, "[BOZ_GL_PROGRAM_LOG] program=%u length=%d text=%.250s\n",
                        program, (int)length, info);
            }
        }
    }
}

static S3E_SOFTFP void host_glUseProgram(GLuint program) {
    void (*real)(GLuint) = lookup_gl("glUseProgram");
    if (real) real(program);
    ++g_boz_gl_program_uses;
    if (boz_shader_diag_enabled() &&
        (g_boz_gl_program_uses <= 24u || program != g_boz_last_program))
        fprintf(stderr, "[BOZ_GL_PROGRAM_USE] seq=%u program=%u prev=%u resolved=%d\n",
                g_boz_gl_program_uses, program, g_boz_last_program, real != NULL);
    g_boz_last_program = program;
}

/* Count actual GL commands, not merely successful window swaps. */
static S3E_SOFTFP void host_glClear(GLbitfield mask) {
    ++g_boz_gl_clear_count;
    unsigned frame = g_boz_visual_probe_next_swap;
    if (boz_texture_diag_enabled() &&
        (frame == 275u || frame == 300u || frame == 305u ||
         frame == 310u || frame == 315u || frame == 320u)) {
        GLfloat color[4] = {0};
        GLint scissor[4] = {0};
        void (*get_float)(GLenum, GLfloat *) = lookup_gl("glGetFloatv");
        void (*get_int)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
        GLboolean (*enabled)(GLenum) = lookup_gl("glIsEnabled");
        if (get_float) get_float(0x0c22u, color); /* GL_COLOR_CLEAR_VALUE */
        if (get_int) get_int(0x0c10u, scissor);  /* GL_SCISSOR_BOX */
        fprintf(stderr,
                "[BOZ_GL_CLEAR_CAUSE] frame=%u mask=%04x fbo=%u "
                "rgba=%g,%g,%g,%g scissor_on=%d rect=%d,%d,%d,%d "
                "caller=%08lx\n",
                frame, (unsigned)mask, g_bound_framebuffer,
                (double)color[0], (double)color[1], (double)color[2],
                (double)color[3],
                enabled ? (int)enabled(0x0c11u) : -1,
                scissor[0], scissor[1], scissor[2], scissor[3],
                (unsigned long)(uintptr_t)__builtin_return_address(0));
    }
    void (*real)(GLbitfield) = lookup_gl("glClear");
    if (real) real(mask);
}

/* Capture post-draw pixels from both GL draw entry points. The original
 * indexed-only trail missed most draws during the late frontend scene. */
static void boz_trace_draw_pixels(const char *kind, unsigned seq, GLsizei count) {
    if (!boz_texture_diag_enabled() ||
        g_boz_visual_probe_next_swap != 300u || g_bound_framebuffer != 0u)
        return;
    void (*read_pixels)(GLint, GLint, GLsizei, GLsizei,
                        GLenum, GLenum, void *) = lookup_gl("glReadPixels");
    void (*get_int)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
    if (!read_pixels) return;
    unsigned char samples[321u * 4u] = {0};
    GLint program = -1;
    if (get_int) get_int(0x8b8du, &program); /* GL_CURRENT_PROGRAM */
    read_pixels(320, 80, 1, 321, 0x1908u, 0x1401u, samples);
    const unsigned char *bottom = samples;
    const unsigned char *middle = samples + 160u * 4u;
    const unsigned char *top = samples + 320u * 4u;
    fprintf(stderr,
            "[BOZ_GL_PIXEL_TRAIL] frame=300 order=%u kind=%s seq=%u "
            "program=%d tex=%u bottom=%02x%02x%02x "
            "middle=%02x%02x%02x top=%02x%02x%02x count=%d\n",
            g_boz_gl_draw_command_count, kind, seq, (int)program,
            g_boz_tex_bound[0], bottom[0], bottom[1], bottom[2],
            middle[0], middle[1], middle[2],
            top[0], top[1], top[2], (int)count);
}

/* Capture a compact first-use program/attribute signature for real array
 * draws in the late frontend, without dereferencing any guest vertex data. */
static void boz_trace_array_geometry(GLenum mode, GLint first, GLsizei count) {
    if (!boz_texture_diag_enabled() || g_boz_visual_probe_next_swap != 300u)
        return;
    void (*get_int)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
    if (!get_int) return;
    GLint program = 0;
    get_int(0x8b8du, &program); /* GL_CURRENT_PROGRAM */
    if (program < 0 || program >= (GLint)sizeof(g_boz_array_program_sampled) ||
        g_boz_array_program_sampled[program])
        return;
    g_boz_array_program_sampled[program] = 1;
    GLint fbo = -1;
    get_int(0x8ca6u, &fbo);
    fprintf(stderr, "[BOZ_GL_ARRAY_PROGRAM] frame=300 program=%d mode=%04x "
            "first=%d count=%d fbo=%d tex=%u order=%u\n",
            program, (unsigned)mode, first, (int)count, fbo,
            g_boz_tex_bound[0], g_boz_gl_draw_command_count);
    void (*get_prog)(GLuint, GLenum, GLint *) = lookup_gl("glGetProgramiv");
    void (*get_attr)(GLuint, GLuint, GLsizei, GLsizei *, GLint *,
                     GLenum *, char *) = lookup_gl("glGetActiveAttrib");
    GLint (*get_attr_loc)(GLuint, const char *) = lookup_gl("glGetAttribLocation");
    void (*get_vertex)(GLuint, GLenum, GLint *) = lookup_gl("glGetVertexAttribiv");
    void (*get_vertex_ptr)(GLuint, GLenum, void **) =
        lookup_gl("glGetVertexAttribPointerv");
    if (!get_prog || !get_attr || !get_attr_loc || !get_vertex)
        return;
    GLint active = 0;
    get_prog((GLuint)program, 0x8b89u, &active); /* GL_ACTIVE_ATTRIBUTES */
    for (GLint index = 0; index < active && index < 12; ++index) {
        char name[96] = {0};
        GLsizei name_len = 0;
        GLint array_size = 0;
        GLenum type = 0;
        get_attr((GLuint)program, (GLuint)index, (GLsizei)sizeof(name),
                 &name_len, &array_size, &type, name);
        GLint location = get_attr_loc((GLuint)program, name);
        if (location < 0) continue;
        GLint enabled = 0, dimension = 0, vertex_type = 0, stride = 0, vbo = 0;
        get_vertex((GLuint)location, 0x8622u, &enabled);
        get_vertex((GLuint)location, 0x8623u, &dimension);
        get_vertex((GLuint)location, 0x8625u, &vertex_type);
        get_vertex((GLuint)location, 0x8624u, &stride);
        get_vertex((GLuint)location, 0x889fu, &vbo);
        void *ptr = NULL;
        if (get_vertex_ptr)
            get_vertex_ptr((GLuint)location, 0x8645u, &ptr);
        fprintf(stderr,
                "[BOZ_GL_ARRAY_ATTR] frame=300 program=%d name=%s loc=%d "
                "enabled=%d size=%d type=%04x stride=%d vbo=%d ptr=%08lx\n",
                program, name, location, enabled, dimension,
                (unsigned)vertex_type, stride, vbo,
                (unsigned long)(uintptr_t)ptr);
    }
    void (*get_uniform)(GLuint, GLuint, GLsizei, GLsizei *, GLint *,
                        GLenum *, char *) = lookup_gl("glGetActiveUniform");
    GLint (*get_loc)(GLuint, const char *) = lookup_gl("glGetUniformLocation");
    void (*get_float_uniform)(GLuint, GLint, GLfloat *) =
        lookup_gl("glGetUniformfv");
    if (!get_uniform || !get_loc || !get_float_uniform) return;
    GLint uniforms = 0;
    get_prog((GLuint)program, 0x8b86u, &uniforms);
    for (GLint i = 0; i < uniforms && i < 12; ++i) {
        char name[96] = {0};
        GLsizei length = 0;
        GLint count_values = 0;
        GLenum type = 0;
        get_uniform((GLuint)program, (GLuint)i, (GLsizei)sizeof(name),
                    &length, &count_values, &type, name);
        GLint loc = get_loc((GLuint)program, name);
        GLfloat floats[16] = {0};
        if (loc >= 0 && count_values == 1 && type != 0x8b5eu &&
            type != 0x8b60u)
            get_float_uniform((GLuint)program, loc, floats);
        fprintf(stderr,
                "[BOZ_GL_ARRAY_UNIFORM] frame=300 program=%d name=%s "
                "loc=%d type=%04x count=%d v=%g,%g,%g,%g\n",
                program, name, loc, (unsigned)type, count_values,
                (double)floats[0], (double)floats[1],
                (double)floats[2], (double)floats[3]);
    }
}

static S3E_SOFTFP void host_glDrawArrays(GLenum mode, GLint first, GLsizei count) {
    ++g_boz_gl_draw_arrays_count;
    ++g_boz_gl_draw_command_count;
    boz_census_draw();
    boz_trace_array_geometry(mode, first, count);
    void (*real)(GLenum, GLint, GLsizei) = lookup_gl("glDrawArrays");
    unsigned frame = g_boz_visual_probe_next_swap;
    bool compare = boz_visual_probe_enabled();
    bool no_cull = compare && ((frame >= 301u && frame <= 306u) ||
                               (frame >= 313u && frame <= 318u));
    bool force_blend = compare && frame >= 307u && frame <= 318u;
    bool restore_cull = false, restore_blend = false;
    if (real && (no_cull || force_blend)) {
        GLboolean (*enabled)(GLenum) = lookup_gl("glIsEnabled");
        void (*enable)(GLenum) = lookup_gl("glEnable");
        void (*disable)(GLenum) = lookup_gl("glDisable");
        if (enabled && enable && disable) {
            if (no_cull && enabled(0x0b44u)) {
                disable(0x0b44u);
                restore_cull = true;
            }
            if (force_blend && !enabled(0x0be2u)) {
                enable(0x0be2u);
                restore_blend = true;
            }
        }
    }
    bool layer_probe = real && boz_layer_probe_enabled();
    GLuint active_tex = g_boz_tex_bound[0];
    bool target_layer = active_tex == 379u || active_tex == 380u;
    bool skip_gray = frame >= 301u && frame <= 306u && active_tex == 379u;
    bool skip_bars = frame >= 307u && frame <= 312u && active_tex == 380u;
    bool skip_both = frame >= 313u && frame <= 318u && target_layer;
    bool skip_layer = layer_probe && (skip_gray || skip_bars || skip_both);
    if (real && !skip_layer) {
        real(mode, first, count);
        boz_trace_draw_pixels("arrays", g_boz_gl_draw_arrays_count, count);
    }
    if (skip_layer) {
        GLint program = -1;
        void (*get_int)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
        if (get_int) get_int(0x8b8du, &program);
        fprintf(stderr,
                "[BOZ_GL_LAYER_AB] frame=%u draw=%u program=%d "
                "tex=%u skipped=1 mode=%04x count=%d\n",
                frame, g_boz_gl_draw_arrays_count, (int)program,
                active_tex, (unsigned)mode, (int)count);
    }
    if (restore_blend) {
        void (*disable)(GLenum) = lookup_gl("glDisable");
        if (disable) disable(0x0be2u);
    }
    if (restore_cull) {
        void (*enable)(GLenum) = lookup_gl("glEnable");
        if (enable) enable(0x0b44u);
    }
    if (compare && (frame == 300u || frame == 305u ||
                    frame == 310u || frame == 315u || frame == 320u) &&
        frame != g_boz_array_ab_logged_swap) {
        g_boz_array_ab_logged_swap = frame;
        fprintf(stderr, "[BOZ_GL_ARRAY_AB] frame=%u draw=%u "
                "no_cull=%d force_blend=%d changed_cull=%d "
                "changed_blend=%d\n", frame, g_boz_gl_draw_arrays_count,
                no_cull, force_blend, restore_cull, restore_blend);
    }
}

static S3E_SOFTFP void host_glDrawElements(GLenum mode, GLsizei count, GLenum type, const void *indices) {
    ++g_boz_gl_draw_elements_count;
    ++g_boz_gl_draw_command_count;
    boz_census_draw();
    void (*real)(GLenum, GLsizei, GLenum, const void *) = lookup_gl("glDrawElements");
    const char *trace = getenv("BOZ_GL_DRAW_DIAGNOSTIC");
    const char *late = getenv("BOZ_GL_LATE_FRAMES");
    const bool late_diag = late && strcmp(late, "1") == 0;
    const bool draw_sample = g_boz_gl_draw_elements_count <= 12u ||
        (late_diag && (g_boz_gl_draw_elements_count % 25u) == 0u);
    const bool diagnostic = trace && strcmp(trace, "1") == 0 && draw_sample;
    if (diagnostic) {
        fprintf(stderr,
                "[BOZ_GL_CALLSITE] kind=draw seq=%u caller=%08lx sampler0=%u\n",
                g_boz_gl_draw_elements_count,
                (unsigned long)(uintptr_t)__builtin_return_address(0),
                g_boz_tex_bound[0]);
        void (*get_int)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
        GLboolean (*is_enabled)(GLenum) = lookup_gl("glIsEnabled");
        GLint viewport[4] = {0}, scissor[4] = {0};
        GLint program = -1, framebuffer = -1, array_buffer = -1, index_buffer = -1;
        if (get_int) {
            get_int(0x0ba2u, viewport); /* GL_VIEWPORT */
            get_int(0x0c10u, scissor);  /* GL_SCISSOR_BOX */
            get_int(0x8b8du, &program); /* GL_CURRENT_PROGRAM */
            get_int(0x8ca6u, &framebuffer); /* GL_FRAMEBUFFER_BINDING */
            get_int(0x8894u, &array_buffer); /* GL_ARRAY_BUFFER_BINDING */
            get_int(0x8895u, &index_buffer); /* GL_ELEMENT_ARRAY_BUFFER_BINDING */
        }
        int scissor_enabled = is_enabled ? (int)is_enabled(0x0c11u) : -1;
        if (boz_texture_diag_enabled()) {
            GLint src_rgb = -1, dst_rgb = -1;
            if (get_int) {
                get_int(0x80c9u, &src_rgb); /* GL_BLEND_SRC_RGB */
                get_int(0x80c8u, &dst_rgb); /* GL_BLEND_DST_RGB */
            }
            fprintf(stderr,
                    "[BOZ_GL_DRAW_STATE] seq=%u program=%d blend=%d "
                    "src=%04x dst=%04x depth=%d cull=%d\n",
                    g_boz_gl_draw_elements_count, program,
                    is_enabled ? (int)is_enabled(0x0be2u) : -1,
                    (unsigned)src_rgb, (unsigned)dst_rgb,
                    is_enabled ? (int)is_enabled(0x0b71u) : -1,
                    is_enabled ? (int)is_enabled(0x0b44u) : -1);
        }
        if (boz_texture_diag_enabled() && get_int) {
            GLint active_texture = 0, active_bound = 0;
            get_int(0x84e0u, &active_texture); /* GL_ACTIVE_TEXTURE */
            get_int(0x8069u, &active_bound);   /* GL_TEXTURE_BINDING_2D */
            GLuint sampler_texture = g_boz_tex_bound[0];
            struct boz_tex_meta *meta = boz_find_tex(sampler_texture, false);
            fprintf(stderr,
                    "[BOZ_GL_TEXTURE_DRAW] seq=%u sampler0_tex=%u active=%04x "
                    "active_bound=%d upload_count=%u image=%dx%d compressed=%u hash64=%016llx "
                    "first=%02x%02x%02x%02x\n",
                    g_boz_gl_draw_elements_count, sampler_texture,
                    (unsigned)active_texture, active_bound, meta ? meta->uploads : 0u,
                    meta ? (int)meta->width : 0, meta ? (int)meta->height : 0,
                    meta ? meta->compressed : 0u,
                    meta ? meta->sample_hash : 0ULL,
                    meta ? meta->first_rgba[0] : 0u,
                    meta ? meta->first_rgba[1] : 0u,
                    meta ? meta->first_rgba[2] : 0u,
                    meta ? meta->first_rgba[3] : 0u);
        }
        /* The shader decides which texture unit is sampled. Unit zero alone
         * cannot prove what an indexed draw actually uses. Log bound sampler
         * units without accessing or retaining any texture pixels. */
        if (boz_texture_diag_enabled() && program > 0) {
            void (*get_program_iv)(GLuint, GLenum, GLint *) =
                lookup_gl("glGetProgramiv");
            void (*get_active_uniform)(GLuint, GLuint, GLsizei, GLsizei *,
                                       GLint *, GLenum *, char *) =
                lookup_gl("glGetActiveUniform");
            GLint (*get_uniform_location)(GLuint, const char *) =
                lookup_gl("glGetUniformLocation");
            void (*get_uniform_iv)(GLuint, GLint, GLint *) =
                lookup_gl("glGetUniformiv");
            if (get_program_iv && get_active_uniform &&
                get_uniform_location && get_uniform_iv) {
                GLint n_uniforms = 0;
                get_program_iv((GLuint)program, 0x8b86u, &n_uniforms);
                for (GLint n = 0; n < n_uniforms && n < 20; ++n) {
                    char uniform_name[96] = {0};
                    GLsizei name_len = 0;
                    GLint uniform_count = 0;
                    GLenum uniform_type = 0;
                    get_active_uniform((GLuint)program, (GLuint)n,
                                       (GLsizei)sizeof(uniform_name),
                                       &name_len, &uniform_count,
                                       &uniform_type, uniform_name);
                    if (uniform_type != 0x8b5eu && uniform_type != 0x8b60u)
                        continue;
                    GLint location = get_uniform_location((GLuint)program, uniform_name);
                    GLint unit = -1;
                    if (location >= 0) get_uniform_iv((GLuint)program, location, &unit);
                    GLuint bound_tex = (unit >= 0 && unit < BOZ_TEX_UNITS) ?
                        g_boz_tex_bound[unit] : 0u;
                    struct boz_tex_meta *tex = boz_find_tex(bound_tex, false);
                    fprintf(stderr,
                            "[BOZ_GL_SAMPLER_BIND] seq=%u program=%d name=%s "
                            "type=%04x unit=%d tex=%u image=%dx%d uploads=%u\n",
                            g_boz_gl_draw_elements_count, program,
                            uniform_name, (unsigned)uniform_type, unit,
                            bound_tex, tex ? (int)tex->width : 0,
                            tex ? (int)tex->height : 0,
                            tex ? tex->uploads : 0u);
                }
            }
        }
        /* Observe the exact UV transform used by the currently linked shader
         * and the sampling state on texture unit zero. Neither query changes GL. */
        if (boz_texture_diag_enabled() && program > 0) {
            GLint (*get_location)(GLuint, const char *) =
                lookup_gl("glGetUniformLocation");
            void (*get_uniformfv)(GLuint, GLint, GLfloat *) =
                lookup_gl("glGetUniformfv");
            if (get_location && get_uniformfv) {
                GLint scale_loc = get_location((GLuint)program, "inUVScale");
                GLint offset_loc = get_location((GLuint)program, "inUVOffset");
                GLfloat scale[4] = {0}, offset[4] = {0};
                if (scale_loc >= 0) get_uniformfv((GLuint)program, scale_loc, scale);
                if (offset_loc >= 0) get_uniformfv((GLuint)program, offset_loc, offset);
                fprintf(stderr,
                        "[BOZ_GL_UV_STATE] seq=%u program=%d scale_loc=%d "
                        "scale=%g,%g offset_loc=%d offset=%g,%g\n",
                        g_boz_gl_draw_elements_count, program, scale_loc,
                        (double)scale[0], (double)scale[1], offset_loc,
                        (double)offset[0], (double)offset[1]);
            }
            GLint active_unit = -1;
            if (get_int) get_int(0x84e0u, &active_unit);
            void (*get_texparam)(GLenum, GLenum, GLint *) =
                lookup_gl("glGetTexParameteriv");
            if (active_unit == 0x84c0 && get_texparam) {
                GLint min_filter = -1, mag_filter = -1, wrap_s = -1, wrap_t = -1;
                get_texparam(0x0de1u, 0x2801u, &min_filter);
                get_texparam(0x0de1u, 0x2800u, &mag_filter);
                get_texparam(0x0de1u, 0x2802u, &wrap_s);
                get_texparam(0x0de1u, 0x2803u, &wrap_t);
                fprintf(stderr,
                        "[BOZ_GL_TEXTURE_PARAMS] seq=%u program=%d tex=%u "
                        "min=%04x mag=%04x wrap_s=%04x wrap_t=%04x\n",
                        g_boz_gl_draw_elements_count, program,
                        g_boz_tex_bound[0], (unsigned)min_filter,
                        (unsigned)mag_filter, (unsigned)wrap_s, (unsigned)wrap_t);
            }
        }
        fprintf(stderr,
                "[BOZ_GL_DRAW] seq=%u mode=%04x count=%d type=%04x indices=%08lx "
                "program=%d fbo_host=%u fbo_gl=%d arr_buf=%d idx_buf=%d "
                "viewport=%d,%d,%d,%d scissor=%d,%d,%d,%d scissor_on=%d resolved=%d\n",
                g_boz_gl_draw_elements_count, mode, count, type,
                (unsigned long)(uintptr_t)indices, program, g_bound_framebuffer,
                framebuffer, array_buffer, index_buffer,
                viewport[0], viewport[1], viewport[2], viewport[3],
                scissor[0], scissor[1], scissor[2], scissor[3],
                scissor_enabled, real != NULL);
        if (g_boz_gl_draw_elements_count == 1u && program > 0) {
            void (*get_program)(GLuint, GLenum, GLint *) = lookup_gl("glGetProgramiv");
            void (*get_active_attrib)(GLuint, GLuint, GLsizei, GLsizei *, GLint *,
                                      GLenum *, char *) = lookup_gl("glGetActiveAttrib");
            GLint link = -1, active_attribs = 0, active_uniforms = 0;
            if (get_program) {
                get_program((GLuint)program, 0x8b82u, &link); /* LINK_STATUS */
                get_program((GLuint)program, 0x8b89u, &active_attribs);
                get_program((GLuint)program, 0x8b86u, &active_uniforms);
            }
            fprintf(stderr,
                    "[BOZ_GL_PROGRAM] id=%d linked=%d attributes=%d uniforms=%d\n",
                    program, link, active_attribs, active_uniforms);
            if (type == 0x1403u && count == 6 && indices && index_buffer == 0) {
                uint16_t first_indices[6] = {0};
                memcpy(first_indices, indices, sizeof(first_indices));
                fprintf(stderr,
                        "[BOZ_GL_INDEX_SAMPLE] seq=1 i=%u,%u,%u,%u,%u,%u\n",
                        (unsigned)first_indices[0], (unsigned)first_indices[1],
                        (unsigned)first_indices[2], (unsigned)first_indices[3],
                        (unsigned)first_indices[4], (unsigned)first_indices[5]);
            }
            void (*get_uniform)(GLuint, GLuint, GLsizei, GLsizei *, GLint *,
                                GLenum *, char *) = lookup_gl("glGetActiveUniform");
            GLint (*get_location)(GLuint, const char *) = lookup_gl("glGetUniformLocation");
            void (*get_uniformfv)(GLuint, GLint, GLfloat *) = lookup_gl("glGetUniformfv");
            void (*get_uniformiv)(GLuint, GLint, GLint *) = lookup_gl("glGetUniformiv");
            if (get_uniform && get_location) {
                for (GLint uniform = 0; uniform < active_uniforms && uniform < 12; ++uniform) {
                    char name[96] = {0};
                    GLsizei name_len = 0;
                    GLint array_size = 0;
                    GLenum uniform_type = 0;
                    get_uniform((GLuint)program, (GLuint)uniform, (GLsizei)sizeof(name),
                                &name_len, &array_size, &uniform_type, name);
                    GLint location = get_location((GLuint)program, name);
                    GLfloat values[16] = {0};
                    if (location >= 0 && get_uniformfv && uniform_type != 0x8b5eu)
                        get_uniformfv((GLuint)program, location, values);
                    GLint texture_unit = -1;
                    if (location >= 0 && get_uniformiv && uniform_type == 0x8b5eu)
                        get_uniformiv((GLuint)program, location, &texture_unit);
                    fprintf(stderr,
                            "[BOZ_GL_UNIFORM] n=%d name=%s type=%04x size=%d loc=%d "
                            "sampler=%d v=%g,%g,%g,%g\n",
                            uniform, name, (unsigned)uniform_type, array_size, location,
                            texture_unit, (double)values[0], (double)values[1],
                            (double)values[2], (double)values[3]);
                    if (uniform_type == 0x8b5cu) {
                        fprintf(stderr,
                                "[BOZ_GL_MATRIX4] name=%s m=%g,%g,%g,%g;%g,%g,%g,%g;"
                                "%g,%g,%g,%g;%g,%g,%g,%g\n",
                                name, (double)values[0], (double)values[1],
                                (double)values[2], (double)values[3],
                                (double)values[4], (double)values[5],
                                (double)values[6], (double)values[7],
                                (double)values[8], (double)values[9],
                                (double)values[10], (double)values[11],
                                (double)values[12], (double)values[13],
                                (double)values[14], (double)values[15]);
                    }
                }
            }
            if (get_active_attrib) {
                for (GLint attribute = 0; attribute < active_attribs && attribute < 12; ++attribute) {
                    char name[96] = {0};
                    GLsizei name_len = 0;
                    GLint attrib_size = 0;
                    GLenum attrib_type = 0;
                    get_active_attrib((GLuint)program, (GLuint)attribute, (GLsizei)sizeof(name),
                                      &name_len, &attrib_size, &attrib_type, name);
                    fprintf(stderr,
                            "[BOZ_GL_ACTIVE_ATTRIB] n=%d name=%s size=%d type=%04x\n",
                            attribute, name, attrib_size, (unsigned)attrib_type);
                }
            }
            void (*get_vertex)(GLuint, GLenum, GLint *) = lookup_gl("glGetVertexAttribiv");
            void (*get_pointer)(GLuint, GLenum, void **) = lookup_gl("glGetVertexAttribPointerv");
            if (get_vertex) {
                for (GLuint attribute = 0; attribute < 8u; ++attribute) {
                    GLint enabled = 0, size = 0, vtype = 0, stride = 0;
                    GLint vbo = 0, norm = 0;
                    get_vertex(attribute, 0x8622u, &enabled); /* ARRAY_ENABLED */
                    if (!enabled) continue;
                    get_vertex(attribute, 0x8623u, &size);   /* ARRAY_SIZE */
                    get_vertex(attribute, 0x8625u, &vtype);  /* ARRAY_TYPE */
                    get_vertex(attribute, 0x8624u, &stride); /* ARRAY_STRIDE */
                    get_vertex(attribute, 0x889fu, &vbo);    /* ARRAY_BUFFER_BINDING */
                    get_vertex(attribute, 0x886au, &norm);   /* NORMALIZED */
                    void *pointer = NULL;
                    if (get_pointer) get_pointer(attribute, 0x8645u, &pointer);
                    fprintf(stderr,
                            "[BOZ_GL_VERTEX_ATTRIB] loc=%u enabled=%d size=%d type=%04x "
                            "stride=%d vbo=%d norm=%d ptr=%08lx\n",
                            attribute, enabled, size, vtype, stride, vbo, norm,
                            (unsigned long)(uintptr_t)pointer);
                    if (vbo == 0 && pointer && (uintptr_t)pointer > 0x10000u) {
                        unsigned char bytes[16];
                        memcpy(bytes, pointer, sizeof(bytes));
                        fprintf(stderr,
                                "[BOZ_GL_VERTEX_BYTES] loc=%u bytes="
                                "%02x%02x%02x%02x%02x%02x%02x%02x"
                                "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                                attribute, bytes[0], bytes[1], bytes[2], bytes[3],
                                bytes[4], bytes[5], bytes[6], bytes[7],
                                bytes[8], bytes[9], bytes[10], bytes[11],
                                bytes[12], bytes[13], bytes[14], bytes[15]);
                    }
                }
            }
        }
    }
    /* Opt-in, reversible A/B experiment on a stable late frontend scene:
     * frame 300=control, 305=no cull, 310=blend, 315=both,
     * frame 320=control again. Restore driver state after each draw. */
    bool compare = boz_visual_probe_enabled();
    unsigned frame = g_boz_visual_probe_next_swap;
    bool no_cull = compare && ((frame >= 301u && frame <= 306u) ||
                               (frame >= 313u && frame <= 318u));
    bool force_blend = compare && frame >= 307u && frame <= 318u;
    GLboolean (*probe_is_enabled)(GLenum) = NULL;
    void (*probe_enable)(GLenum) = NULL;
    void (*probe_disable)(GLenum) = NULL;
    if (real && (no_cull || force_blend)) {
        probe_is_enabled = lookup_gl("glIsEnabled");
        probe_enable = lookup_gl("glEnable");
        probe_disable = lookup_gl("glDisable");
    }
    bool restore_cull = false, restore_blend = false;
    if (probe_is_enabled && probe_enable && probe_disable) {
        if (no_cull && probe_is_enabled(0x0b44u)) {
            probe_disable(0x0b44u); /* GL_CULL_FACE */
            restore_cull = true;
        }
        if (force_blend && !probe_is_enabled(0x0be2u)) {
            probe_enable(0x0be2u); /* GL_BLEND */
            restore_blend = true;
        }
    }
    if (real) real(mode, count, type, indices);
    if (real) boz_trace_draw_pixels("elements", g_boz_gl_draw_elements_count, count);
    if (restore_blend) probe_disable(0x0be2u);
    if (restore_cull) probe_enable(0x0b44u);
    if (compare && (frame == 300u || frame == 305u ||
                    frame == 310u || frame == 315u || frame == 320u) &&
        frame != g_boz_visual_probe_logged_swap) {
        g_boz_visual_probe_logged_swap = frame;
        fprintf(stderr,
                "[BOZ_GL_VISUAL_AB] frame=%u draw=%u no_cull=%d "
                "force_blend=%d changed_cull=%d changed_blend=%d\n",
                frame, g_boz_gl_draw_elements_count, no_cull,
                force_blend, restore_cull, restore_blend);
    }
    if (diagnostic) {
        GLenum (*get_error)(void) = lookup_gl("glGetError");
        if (get_error) {
            fprintf(stderr, "[BOZ_GL_DRAW_ERROR] seq=%u gl_error=0x%04x\n",
                    g_boz_gl_draw_elements_count, (unsigned)get_error());
        }
    }
}

static void driver_bind_framebuffer(GLuint framebuffer) {
    void (*real)(GLenum, GLuint) = lookup_gl("glBindFramebuffer");
    if (!real) {
        real = lookup_gl("glBindFramebufferOES");
    }
    if (real) {
        real(GL_FRAMEBUFFER_VALUE, framebuffer);
    }
}

static void sleep_until_us(uint64_t target_us) {
    for (;;) {
        uint64_t now = monotonic_us();
        if (now >= target_us) {
            return;
        }
        uint64_t remaining = target_us - now;
        struct timespec req = {
            .tv_sec = (time_t)(remaining / 1000000u),
            .tv_nsec = (long)(remaining % 1000000u) * 1000L,
        };
        while (nanosleep(&req, &req) != 0 && errno == EINTR) {
        }
    }
}

static void pace_frame(void) {
    static uint64_t next_frame_us;
    uint64_t now = monotonic_us();

    if (!next_frame_us || now > next_frame_us + FRAME_RESET_US) {
        next_frame_us = now + FRAME_INTERVAL_US;
    }

    sleep_until_us(next_frame_us);
    next_frame_us += FRAME_INTERVAL_US;
}

GL_WRAP_FLOAT2(glAlphaFunc, GLenum, GLfloat)
GL_WRAP_FLOAT4(glBlendColor, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT4(glClearColor, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT1(glClearDepthf, GLfloat)
GL_WRAP_FLOAT1_ALIAS(glClearDepthfOES, glClearDepthf, GLfloat)
GL_WRAP_FLOAT4(glColor4f, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT2(glDepthRangef, GLfloat, GLfloat)
GL_WRAP_FLOAT2_ALIAS(glDepthRangefOES, glDepthRangef, GLfloat, GLfloat)
static S3E_SOFTFP void host_glDrawTexfOES(GLfloat x, GLfloat y, GLfloat z, GLfloat width, GLfloat height) {
    ++g_boz_gl_draw_tex_count;
    void (*real)(GLfloat, GLfloat, GLfloat, GLfloat, GLfloat) = lookup_gl("glDrawTexfOES");
    if (real) real(x, y, z, width, height);
}
GL_WRAP_FLOAT2(glFogf, GLenum, GLfloat)
GL_WRAP_FLOAT6(glFrustumf, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT6_ALIAS(glFrustumfOES, glFrustumf, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat,
                     GLfloat)
GL_WRAP_FLOAT2(glLightModelf, GLenum, GLfloat)
GL_WRAP_FLOAT3(glLightf, GLenum, GLenum, GLfloat)
GL_WRAP_FLOAT1(glLineWidth, GLfloat)
GL_WRAP_FLOAT3(glMaterialf, GLenum, GLenum, GLfloat)
GL_WRAP_FLOAT5(glMultiTexCoord4f, GLenum, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT3(glNormal3f, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT6(glOrthof, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT6_ALIAS(glOrthofOES, glOrthof, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT1(glPointSize, GLfloat)
GL_WRAP_FLOAT2(glPolygonOffset, GLfloat, GLfloat)
GL_WRAP_FLOAT4(glRotatef, GLfloat, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT3(glScalef, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT3(glTexEnvf, GLenum, GLenum, GLfloat)
GL_WRAP_FLOAT3(glTexGenfOES, GLenum, GLenum, GLfloat)
GL_WRAP_FLOAT3(glTranslatef, GLfloat, GLfloat, GLfloat)
GL_WRAP_FLOAT2(glUniform1f, GLint, GLfloat)
GL_WRAP_FLOAT5(glUniform4f, GLint, GLfloat, GLfloat, GLfloat, GLfloat)

static void bind_framebuffer(GLenum target, GLuint framebuffer) {
    if (target == GL_FRAMEBUFFER_VALUE) {
        driver_bind_framebuffer(framebuffer);
        g_bound_framebuffer = framebuffer;
        return;
    }

    void (*real)(GLenum, GLuint) = lookup_gl("glBindFramebuffer");
    if (!real) {
        real = lookup_gl("glBindFramebufferOES");
    }
    if (real) {
        real(target, framebuffer);
    }
}

static S3E_SOFTFP void host_glBindFramebuffer(GLenum target, GLuint framebuffer) {
    bind_framebuffer(target, framebuffer);
}

static S3E_SOFTFP void host_glBindFramebufferOES(GLenum target, GLuint framebuffer) {
    bind_framebuffer(target, framebuffer);
}

static S3E_SOFTFP void host_glViewport(GLint x, GLint y, GLsizei width, GLsizei height) {
    void (*real)(GLint, GLint, GLsizei, GLsizei) = lookup_gl("glViewport");
    if (real) {
        if (!g_bound_framebuffer) {
            x += g_surface.x;
            y += g_surface.y;
        }
        real(x, y, width, height);
    }
}

static S3E_SOFTFP void host_glScissor(GLint x, GLint y, GLsizei width, GLsizei height) {
    void (*real)(GLint, GLint, GLsizei, GLsizei) = lookup_gl("glScissor");
    if (real) {
        if (!g_bound_framebuffer) {
            x += g_surface.x;
            y += g_surface.y;
        }
        real(x, y, width, height);
    }
}

static void map_drawable_rect_to_surface(GLint *rect) {
    GLint left = rect[0] > g_surface.x ? rect[0] : g_surface.x;
    GLint bottom = rect[1] > g_surface.y ? rect[1] : g_surface.y;
    GLint right = rect[0] + rect[2];
    GLint top = rect[1] + rect[3];
    GLint surface_right = g_surface.x + g_surface.width;
    GLint surface_top = g_surface.y + g_surface.height;
    if (right > surface_right) {
        right = surface_right;
    }
    if (top > surface_top) {
        top = surface_top;
    }
    if (left > surface_right) {
        left = surface_right;
    }
    if (bottom > surface_top) {
        bottom = surface_top;
    }
    rect[0] = left - g_surface.x;
    rect[1] = bottom - g_surface.y;
    rect[2] = right > left ? right - left : 0;
    rect[3] = top > bottom ? top - bottom : 0;
}

static S3E_SOFTFP void host_glGetIntegerv(GLenum name, GLint *values) {
    void (*real)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
    if (!real) {
        return;
    }
    real(name, values);
    if (!g_bound_framebuffer && values &&
        (name == GL_VIEWPORT_VALUE || name == GL_SCISSOR_BOX_VALUE)) {
        map_drawable_rect_to_surface(values);
    }
}

static S3E_SOFTFP void host_glReadPixels(GLint x, GLint y, GLsizei width, GLsizei height,
                                         GLenum format, GLenum type, void *pixels) {
    void (*real)(GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, void *) =
        lookup_gl("glReadPixels");
    if (real) {
        if (!g_bound_framebuffer) {
            x += g_surface.x;
            y += g_surface.y;
        }
        real(x, y, width, height, format, type, pixels);
    }
}

static unsigned long long trace_gl_hash64(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    unsigned long long h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static size_t trace_gl_bpp(GLenum format, GLenum type) {
    if (type == 0x8033 || type == 0x8034 || type == 0x8363 || type == 0x8362) return 2;
    if (type == 0x1401 && format == 0x1907) return 3;
    if (type == 0x1401 && format == 0x1908) return 4;
    if (type == 0x1401 && format == 0x1909) return 1;
    if (type == 0x1401 && format == 0x190A) return 2;
    return 0;
}

static void trace_gl_upload_diag(const char *name, GLenum target, GLint level, GLenum internal_format,
                                 GLsizei width, GLsizei height, GLint border, GLenum format,
                                 GLenum type, const void *pixels) {
    const char *enabled = getenv("GL_UPLOAD_TRACE");
    if (!enabled || !*enabled || !pixels || width <= 0 || height <= 0) return;

    size_t bpp = trace_gl_bpp(format, type);
    size_t bytes = bpp ? (size_t)width * (size_t)height * bpp : 0;
    size_t sample = bytes < 4096 ? bytes : 4096;
    unsigned long long hash = sample ? trace_gl_hash64(pixels, sample) : 0;
    size_t ff83 = 0, zero = 0;

    if (bpp == 2) {
        const unsigned short *p = (const unsigned short *)pixels;
        size_t count = (size_t)width * (size_t)height;
        for (size_t i = 0; i < count; ++i) {
            if (p[i] == 0xF83Fu) ++ff83;
            if (p[i] == 0x0000u) ++zero;
        }
    }

    FILE *fp = fopen("/tmp/boz_gl_upload_trace.log", "a");
    if (!fp) return;

    fprintf(fp,
            "[GLUPLOAD] %s target=0x%04x level=%d internal=0x%04x size=%dx%d "
            "border=%d format=0x%04x type=0x%04x ptr=%p bpp=%zu bytes=%zu "
            "sample=%zu hash64=%016llx ff83=%zu zero=%zu first=",
            name, (unsigned)target, level, (unsigned)internal_format,
            (int)width, (int)height, border, (unsigned)format, (unsigned)type,
            pixels, bpp, bytes, sample, hash, ff83, zero);

    const unsigned char *raw = (const unsigned char *)pixels;
    size_t first = sample < 32 ? sample : 32;
    for (size_t i = 0; i < first; ++i) fprintf(fp, "%02x", raw[i]);
    fputc('\n', fp);
    fclose(fp);
}

static void boz_track_tex_upload(GLenum target, GLint level, GLsizei width,
                                 GLsizei height, GLenum format, GLenum type,
                                 const void *pixels, bool sub_image) {
    if (!boz_texture_diag_enabled() || target != 0x0de1u || level != 0 ||
        g_boz_tex_active < 0x84c0u || g_boz_tex_active >= 0x84c0u + BOZ_TEX_UNITS)
        return;
    GLuint texture = g_boz_tex_bound[g_boz_tex_active - 0x84c0u];
    struct boz_tex_meta *meta = boz_find_tex(texture, true);
    if (!meta) return;
    ++meta->uploads;
    ++g_boz_tex_uploads;
    if (width == 2 && height == 2) ++g_boz_tex_size_2x2;
    else if (width > 2 || height > 2) ++g_boz_tex_size_large;
    else ++g_boz_tex_size_other;
    if (sub_image) ++g_boz_tex_sub_uploads;
    if (width > g_boz_tex_max_width) g_boz_tex_max_width = width;
    if (height > g_boz_tex_max_height) g_boz_tex_max_height = height;
    if (!sub_image) {
        meta->compressed = 0;
        meta->width = width;
        meta->height = height;
    }
    meta->sample_hash = 0;
    meta->first_bytes = 0;
    size_t bpp = trace_gl_bpp(format, type);
    if (pixels && width > 0 && height > 0 && bpp &&
        (size_t)width <= SIZE_MAX / (size_t)height / bpp) {
        size_t available = (size_t)width * (size_t)height * bpp;
        size_t sample = available < 512 ? available : 512;
        meta->sample_hash = trace_gl_hash64(pixels, sample);
        meta->first_bytes = (unsigned)(available < 16 ? available : 16);
        memcpy(meta->first_rgba, pixels, meta->first_bytes);
    }
    /* Check sparse byte samples across each large image, not just its first 512 bytes.
     * This distinguishes a genuine empty atlas from a transparent initial row.
     * No source image or complete scan is retained. */
    if (!sub_image && pixels && width > 2 && height > 2 && bpp &&
        (size_t)width <= SIZE_MAX / (size_t)height / bpp) {
        size_t length = (size_t)width * (size_t)height * bpp;
        const unsigned char *bytes = (const unsigned char *)pixels;
        size_t sampled = 0, nonzero = 0, alpha_pixels = 0;
        size_t alpha_nonzero = 0, alpha_opaque = 0;
        unsigned alpha_max = 0;
        if (format == 0x1908u && type == 0x8033u) alpha_max = 15u;
        else if (format == 0x1908u && type == 0x8034u) alpha_max = 1u;
        else if (format == 0x1908u && type == 0x1401u) alpha_max = 255u;
        else if (format == 0x190au && type == 0x1401u) alpha_max = 255u;
        for (unsigned window = 0; window < 5u; ++window) {
            size_t start = window == 4u ? (length > 64u ? length - 64u : 0u)
                                         : length / 4u * window;
            start -= start % bpp;
            size_t take = length - start < 64u ? length - start : 64u;
            for (size_t i = 0; i < take; ++i)
                if (bytes[start + i] != 0u) ++nonzero;
            sampled += take;
            if (!alpha_max) continue;
            for (size_t i = 0; i + bpp <= take; i += bpp) {
                unsigned alpha = 0;
                if (type == 0x8033u) alpha = bytes[start + i] & 0x0fu;
                else if (type == 0x8034u) alpha = bytes[start + i] & 1u;
                else alpha = bytes[start + i + bpp - 1u];
                ++alpha_pixels;
                if (alpha != 0u) ++alpha_nonzero;
                if (alpha == alpha_max) ++alpha_opaque;
            }
        }
        fprintf(stderr,
                "[BOZ_GL_TEXTURE_OCCUPANCY] tex=%u size=%dx%d format=%04x type=%04x "
                "sample_bytes=%zu nonzero_bytes=%zu alpha_pixels=%zu "
                "alpha_nonzero=%zu alpha_opaque=%zu\n",
                texture, (int)width, (int)height, (unsigned)format, (unsigned)type,
                sampled, nonzero, alpha_pixels, alpha_nonzero, alpha_opaque);
    }
    if (g_boz_tex_uploads <= 36u ||
        ((width > 2 || height > 2) && g_boz_tex_large_printed++ < 20u))
        fprintf(stderr,
                "[BOZ_GL_TEXTURE_UPLOAD] n=%u tex=%u sub=%d size=%dx%d "
                "fmt=%04x type=%04x hash64=%016llx\n",
                g_boz_tex_uploads, texture, (int)sub_image, (int)width, (int)height,
                format, type, meta->sample_hash);
}

/* Compressed GLES uploads are separate entry points from glTexImage2D.
 * Record only metadata, preserve the original driver invocation, and never
 * materialize or store compressed texture payloads. */
static S3E_SOFTFP void host_glCompressedTexImage2D(
    GLenum target, GLint level, GLenum internalformat, GLsizei width,
    GLsizei height, GLint border, GLsizei imageSize, const void *data) {
    void (*real)(GLenum, GLint, GLenum, GLsizei, GLsizei, GLint, GLsizei, const void *) =
        lookup_gl("glCompressedTexImage2D");
    if (boz_texture_diag_enabled()) {
        ++g_boz_tex_compressed_uploads;
        if (!real) ++g_boz_tex_compressed_unresolved;
        GLuint tex = 0;
        if (target == 0x0de1u && level == 0 && g_boz_tex_active >= 0x84c0u &&
            g_boz_tex_active < 0x84c0u + BOZ_TEX_UNITS) {
            tex = g_boz_tex_bound[g_boz_tex_active - 0x84c0u];
            struct boz_tex_meta *meta = boz_find_tex(tex, true);
            if (meta) {
                ++meta->uploads;
                meta->compressed = 1;
                meta->width = width;
                meta->height = height;
                meta->first_bytes = 0;
                meta->sample_hash = data && imageSize > 0 ?
                    trace_gl_hash64(data, (size_t)imageSize < 512u ? (size_t)imageSize : 512u) : 0;
            }
        }
        if (g_boz_tex_compressed_uploads <= 24u) {
            fprintf(stderr,
                    "[BOZ_GL_COMPRESSED_UPLOAD] n=%u tex=%u format=%04x level=%d "
                    "size=%dx%d image_bytes=%d resolved=%d\n",
                    g_boz_tex_compressed_uploads, tex, internalformat, level,
                    width, height, imageSize, real != NULL);
        }
    }
    if (real) real(target, level, internalformat, width, height, border, imageSize, data);
}

static S3E_SOFTFP void host_glCompressedTexSubImage2D(
    GLenum target, GLint level, GLint xoffset, GLint yoffset,
    GLsizei width, GLsizei height, GLenum format, GLsizei imageSize, const void *data) {
    void (*real)(GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLsizei, const void *) =
        lookup_gl("glCompressedTexSubImage2D");
    if (boz_texture_diag_enabled()) {
        ++g_boz_tex_compressed_uploads;
        if (!real) ++g_boz_tex_compressed_unresolved;
        GLuint tex = 0;
        if (target == 0x0de1u && level == 0 && g_boz_tex_active >= 0x84c0u &&
            g_boz_tex_active < 0x84c0u + BOZ_TEX_UNITS) {
            tex = g_boz_tex_bound[g_boz_tex_active - 0x84c0u];
            struct boz_tex_meta *meta = boz_find_tex(tex, true);
            if (meta) ++meta->uploads;
        }
        if (g_boz_tex_compressed_uploads <= 24u) {
            fprintf(stderr,
                    "[BOZ_GL_COMPRESSED_SUBUPLOAD] n=%u tex=%u fmt=%04x level=%d "
                    "xy=%d,%d size=%dx%d image_bytes=%d resolved=%d\n",
                    g_boz_tex_compressed_uploads, tex, format, level, xoffset, yoffset,
                    width, height, imageSize, real != NULL);
        }
    }
    if (real) real(target, level, xoffset, yoffset, width, height, format, imageSize, data);
}

static S3E_SOFTFP void host_glTexImage2D(GLenum target, GLint level, GLint internal_format,
                                          GLsizei width, GLsizei height, GLint border,
                                          GLenum format, GLenum type, const void *pixels) {
    void (*real)(GLenum, GLint, GLint, GLsizei, GLsizei, GLint, GLenum, GLenum, const void *) =
        lookup_gl("glTexImage2D");
    trace_gl_upload_diag("glTexImage2D", target, level, (GLenum)internal_format, width, height,
                         border, format, type, pixels);
    boz_track_tex_upload(target, level, width, height, format, type, pixels, false);
    if (boz_texture_diag_enabled() && target == 0x0de1u && level == 0) {
        bool larger = width > 2 || height > 2;
        unsigned seq = larger ? ++g_boz_large_texture_callers :
                                ++g_boz_small_texture_callers;
        if ((larger && seq <= 28u) || (!larger && (seq <= 8u || seq % 100u == 0u))) {
            unsigned unit = g_boz_tex_active - 0x84c0u;
            GLuint tex = unit < BOZ_TEX_UNITS ? g_boz_tex_bound[unit] : 0u;
            fprintf(stderr,
                    "[BOZ_GL_CALLSITE] kind=upload seq=%u caller=%08lx "
                    "unit=%u tex=%u size=%dx%d\n",
                    seq, (unsigned long)(uintptr_t)__builtin_return_address(0),
                    unit, tex, (int)width, (int)height);
        }
    }
    if (real) real(target, level, internal_format, width, height, border, format, type, pixels);
}

static S3E_SOFTFP void host_glTexSubImage2D(GLenum target, GLint level, GLint xoffset, GLint yoffset,
                                             GLsizei width, GLsizei height, GLenum format,
                                             GLenum type, const void *pixels) {
    void (*real)(GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLenum,
                 const void *) = lookup_gl("glTexSubImage2D");
    trace_gl_upload_diag("glTexSubImage2D", target, level, 0, width, height, 0, format, type, pixels);
    boz_track_tex_upload(target, level, width, height, format, type, pixels, true);
    if (real) real(target, level, xoffset, yoffset, width, height, format, type, pixels);
}

static S3E_SOFTFP void host_glCopyTexImage2D(GLenum target, GLint level, GLenum internal_format,
                                             GLint x, GLint y, GLsizei width, GLsizei height,
                                             GLint border) {
    void (*real)(GLenum, GLint, GLenum, GLint, GLint, GLsizei, GLsizei, GLint) =
        lookup_gl("glCopyTexImage2D");
    if (real) {
        if (!g_bound_framebuffer) {
            x += g_surface.x;
            y += g_surface.y;
        }
        real(target, level, internal_format, x, y, width, height, border);
    }
}

static S3E_SOFTFP void host_glCopyTexSubImage2D(GLenum target, GLint level, GLint x_offset,
                                                GLint y_offset, GLint x, GLint y, GLsizei width,
                                                GLsizei height) {
    void (*real)(GLenum, GLint, GLint, GLint, GLint, GLint, GLsizei, GLsizei) =
        lookup_gl("glCopyTexSubImage2D");
    if (real) {
        if (!g_bound_framebuffer) {
            x += g_surface.x;
            y += g_surface.y;
        }
        real(target, level, x_offset, y_offset, x, y, width, height);
    }
}

struct host_symbol {
    const char *name;
    void *fn;
};

static void *resolve_wrapped_host_proc(const char *symbol);

static void *host_eglGetProcAddress(const char *procname) {
    if (!procname) {
        return NULL;
    }
    void *wrapped = resolve_wrapped_host_proc(procname);
    if (wrapped) {
        return wrapped;
    }
    void *egl = egl_backend_resolve(procname);
    return egl ? egl : egl_backend_get_proc_address(procname);
}

static void cursor_clear_rect(GLint x, GLint y, GLsizei w, GLsizei h,
                              void (*gl_scissor)(GLint, GLint, GLsizei, GLsizei),
                              void (*gl_clear)(GLbitfield)) {
    if (w <= 0 || h <= 0) {
        return;
    }
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x + w > g_surface.width) {
        w = g_surface.width - x;
    }
    if (y + h > g_surface.height) {
        h = g_surface.height - y;
    }
    if (w <= 0 || h <= 0) {
        return;
    }
    GLint gl_y = (GLint)g_surface.height - y - h;
    gl_scissor(g_surface.x + x, g_surface.y + gl_y, w, h);
    gl_clear(GL_COLOR_BUFFER_BIT_VALUE);
}

static int cursor_scaled_size(int size) {
    uint32_t width_scale = (uint32_t)g_surface.width * REFERENCE_SURFACE_HEIGHT;
    uint32_t height_scale = (uint32_t)g_surface.height * REFERENCE_SURFACE_WIDTH;
    uint32_t scale = width_scale < height_scale ? width_scale : height_scale;
    uint32_t reference_area = REFERENCE_SURFACE_WIDTH * REFERENCE_SURFACE_HEIGHT;
    int result = (int)(((uint64_t)size * scale + reference_area / 2u) / reference_area);
    return result > 0 ? result : 1;
}

static void clear_letterbox_rect(GLint x, GLint y, GLsizei width, GLsizei height,
                                 void (*gl_scissor)(GLint, GLint, GLsizei, GLsizei),
                                 void (*gl_clear)(GLbitfield)) {
    if (width > 0 && height > 0) {
        gl_scissor(x, y, width, height);
        gl_clear(GL_COLOR_BUFFER_BIT_VALUE);
    }
}

static void frontend_overlay_gl_present(void) {
    int has_letterbox = g_surface.x || g_surface.y;
    if (!has_letterbox && !g_cursor_active) {
        return;
    }

    void (*gl_disable)(GLenum) = lookup_gl("glDisable");
    void (*gl_enable)(GLenum) = lookup_gl("glEnable");
    GLboolean (*gl_is_enabled)(GLenum) = lookup_gl("glIsEnabled");
    void (*gl_scissor)(GLint, GLint, GLsizei, GLsizei) = lookup_gl("glScissor");
    void (*gl_clear_color)(GLfloat, GLfloat, GLfloat, GLfloat) = lookup_gl("glClearColor");
    void (*gl_clear)(GLbitfield) = lookup_gl("glClear");
    void (*gl_get_integerv)(GLenum, GLint *) = lookup_gl("glGetIntegerv");
    void (*gl_get_floatv)(GLenum, GLfloat *) = lookup_gl("glGetFloatv");
    void (*gl_get_booleanv)(GLenum, GLboolean *) = lookup_gl("glGetBooleanv");
    void (*gl_color_mask)(GLboolean, GLboolean, GLboolean, GLboolean) = lookup_gl("glColorMask");
    if (!gl_disable || !gl_enable || !gl_is_enabled || !gl_scissor || !gl_clear_color ||
        !gl_clear || !gl_get_integerv || !gl_get_floatv || !gl_get_booleanv || !gl_color_mask) {
        return;
    }

    GLboolean scissor_was_enabled = gl_is_enabled(GL_SCISSOR_TEST_VALUE);
    GLint scissor_box[4] = {0, 0, 0, 0};
    GLfloat clear_color[4] = {0, 0, 0, 0};
    GLboolean color_mask[4] = {1, 1, 1, 1};
    gl_get_integerv(GL_SCISSOR_BOX_VALUE, scissor_box);
    gl_get_floatv(GL_COLOR_CLEAR_VALUE, clear_color);
    gl_get_booleanv(GL_COLOR_WRITEMASK_VALUE, color_mask);

    if (!scissor_was_enabled) {
        gl_enable(GL_SCISSOR_TEST_VALUE);
    }
    gl_color_mask(1, 1, 1, 1);
    gl_clear_color(0.0f, 0.0f, 0.0f, 1.0f);

    if (has_letterbox) {
        GLint right = g_surface.x + g_surface.width;
        GLint top = g_surface.y + g_surface.height;
        clear_letterbox_rect(0, 0, g_surface.x, g_native_window.height, gl_scissor, gl_clear);
        clear_letterbox_rect(right, 0, g_native_window.width - right, g_native_window.height,
                             gl_scissor, gl_clear);
        clear_letterbox_rect(g_surface.x, 0, g_surface.width, g_surface.y, gl_scissor, gl_clear);
        clear_letterbox_rect(g_surface.x, top, g_surface.width, g_native_window.height - top,
                             gl_scissor, gl_clear);
    }

    if (g_cursor_active) {
        int x = g_pointer_x;
        int y = g_pointer_y;
        const int outline_radius = cursor_scaled_size(10);
        const int outline_thickness = cursor_scaled_size(5);
        const int inner_radius = cursor_scaled_size(8);
        const int inner_thickness = cursor_scaled_size(3);

        gl_clear_color(0.0f, 0.0f, 0.0f, 1.0f);
        cursor_clear_rect(x - outline_radius, y - outline_thickness / 2, outline_radius * 2 + 1,
                          outline_thickness, gl_scissor, gl_clear);
        cursor_clear_rect(x - outline_thickness / 2, y - outline_radius, outline_thickness,
                          outline_radius * 2 + 1, gl_scissor, gl_clear);
        gl_clear_color(0.1f, 0.55f, 1.0f, 1.0f);
        cursor_clear_rect(x - inner_radius, y - inner_thickness / 2, inner_radius * 2 + 1,
                          inner_thickness, gl_scissor, gl_clear);
        cursor_clear_rect(x - inner_thickness / 2, y - inner_radius, inner_thickness,
                          inner_radius * 2 + 1, gl_scissor, gl_clear);
    }

    gl_clear_color(clear_color[0], clear_color[1], clear_color[2], clear_color[3]);
    gl_color_mask(color_mask[0], color_mask[1], color_mask[2], color_mask[3]);
    gl_scissor(scissor_box[0], scissor_box[1], scissor_box[2], scissor_box[3]);
    if (!scissor_was_enabled) {
        gl_disable(GL_SCISSOR_TEST_VALUE);
    }
}

/* Diagnostic-only, opt-in real framebuffer capture before a swap.
 * PPM is intentionally used here so the ARM loader needs no PNG dependency. */
static void boz_capture_swap_frame(unsigned frame, bool pre_overlay) {
    const char *dir = getenv("BOZ_FRAME_CAPTURE_DIR");
    if (pre_overlay && frame != 275u && frame != 300u &&
        frame != 305u && frame != 310u && frame != 315u &&
        frame != 320u && frame != 325u)
        return;
    if (!dir || !*dir ||
        (frame != 1u && frame != 5u && frame != 10u && frame != 15u &&
         frame != 60u && frame != 100u && frame != 125u &&
         frame != 130u && frame != 140u && frame != 150u &&
         frame != 175u && frame != 200u && frame != 225u &&
         frame != 185u && frame != 190u && frame != 195u &&
         frame != 250u && frame != 275u && frame != 300u &&
         frame != 305u && frame != 310u && frame != 315u &&
         frame != 320u && frame != 325u && frame != 350u &&
         frame != 375u && frame != 400u)) return;
    void (*read_pixels)(GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, void *) =
        lookup_gl("glReadPixels");
    if (!read_pixels) {
        fprintf(stderr, "[BOZ_FRAME_CAPTURE] n=%u error=no_glReadPixels\n", frame);
        return;
    }
    const size_t width = REFERENCE_SURFACE_WIDTH;
    const size_t height = REFERENCE_SURFACE_HEIGHT;
    const size_t n_pixels = width * height;
    uint8_t *rgba = malloc(n_pixels * 4u);
    uint8_t *rgb = malloc(n_pixels * 3u);
    if (!rgba || !rgb) {
        free(rgba);
        free(rgb);
        fprintf(stderr, "[BOZ_FRAME_CAPTURE] n=%u error=allocation\n", frame);
        return;
    }
    read_pixels(0, 0, (GLsizei)width, (GLsizei)height, 0x1908u, 0x1401u, rgba);
    uint32_t hash = 2166136261u;
    for (size_t y = 0; y < height; ++y) {
        const size_t src_row = height - 1u - y;
        for (size_t x = 0; x < width; ++x) {
            const size_t src = (src_row * width + x) * 4u;
            const size_t dst = (y * width + x) * 3u;
            for (size_t k = 0; k < 3u; ++k) {
                rgb[dst + k] = rgba[src + k];
                hash = (hash ^ rgb[dst + k]) * 16777619u;
            }
        }
    }
    char filename[512];
    int len = snprintf(filename, sizeof(filename), pre_overlay ?
                       "%s/boz-pre-overlay-%05u.ppm" : "%s/boz-swap-%05u.ppm",
                       dir, frame);
    FILE *fp = len > 0 && (size_t)len < sizeof(filename) ? fopen(filename, "wb") : NULL;
    if (fp) {
        fprintf(fp, "P6\n%zu %zu\n255\n", width, height);
        size_t wrote = fwrite(rgb, 1, n_pixels * 3u, fp);
        fclose(fp);
        fprintf(stderr,
                "[BOZ_FRAME_CAPTURE] n=%u pixels=%zu hash=%08x write_ok=%d file=%s\n",
                frame, n_pixels, hash, wrote == n_pixels * 3u, filename);
    } else {
        fprintf(stderr, "[BOZ_FRAME_CAPTURE] n=%u error=failed_to_open\n", frame);
    }
    free(rgb);
    free(rgba);
}

static EGLBoolean host_eglSwapBuffers(EGLDisplay display, EGLSurface surface) {
    static unsigned swap_count;
    static uint64_t first_swap_ms;
    const char *trace_swap = getenv("BOZ_SWAP_PROGRESS");
    const bool trace_enabled = trace_swap && strcmp(trace_swap, "1") == 0;
    ++swap_count;
    if (!first_swap_ms) first_swap_ms = monotonic_us() / 1000u;
    input_pump();
    /* Diagnostic tap after the genuine frontend group finishes loading.
     * At 150-swap CI baseline, the group closes between swaps 100 and 125;
     * the legacy frame-5 tap was prematurely delivered during loading.
     * Never inject input into normal runs unless explicitly requested. */
    const char *late_tap = getenv("BOZ_DIAGNOSTIC_LATE_TAP");
    if (late_tap && strcmp(late_tap, "1") == 0) {
        if (swap_count == 125u) {
            fprintf(stderr, "[BOZ_LATE_TAP] swap=125 stage=press\n");
            input_diagnostic_tap_step(1);
        } else if (swap_count == 126u) {
            fprintf(stderr, "[BOZ_LATE_TAP] swap=126 stage=release\n");
            input_diagnostic_tap_step(0);
        }
    }
    const char *auto_tap = getenv("BOZ_DIAGNOSTIC_AUTO_TAP");
    if (auto_tap && strcmp(auto_tap, "1") == 0) {
        if (swap_count == 5u) {
            input_diagnostic_tap_step(1);
        } else if (swap_count == 6u) {
            input_diagnostic_tap_step(0);
        }
    }
    dispatch_due_timers();
    GLuint previous_framebuffer = g_bound_framebuffer;
    if (previous_framebuffer) {
        driver_bind_framebuffer(0);
    }
    if (trace_enabled && (swap_count == 275u || swap_count == 300u ||
                          swap_count == 305u || swap_count == 310u ||
                          swap_count == 315u || swap_count == 320u ||
                          swap_count == 325u))
        boz_capture_swap_frame(swap_count, true);
    frontend_overlay_gl_present();
    if (trace_enabled) boz_capture_swap_frame(swap_count, false);
    if (previous_framebuffer) {
        driver_bind_framebuffer(previous_framebuffer);
    }
    EGLBoolean result = egl_backend_swap_buffers(display, surface);
    if (trace_enabled && (swap_count <= 5u || swap_count % 5u == 0u)) {
        fprintf(stderr,
                "[BOZ_SWAP_PROGRESS] n=%u ok=%d fbo=%u elapsed_ms=%llu gl_clear=%u gl_draw_arrays=%u gl_draw_elements=%u gl_draw_tex=%u\n",
                swap_count, (int)result, (unsigned)previous_framebuffer,
                (unsigned long long)(monotonic_us() / 1000u - first_swap_ms),
                g_boz_gl_clear_count, g_boz_gl_draw_arrays_count,
                g_boz_gl_draw_elements_count, g_boz_gl_draw_tex_count);
    }
    if (boz_texture_diag_enabled() &&
        (swap_count == 5u || swap_count == 60u || swap_count == 100u ||
         swap_count == 150u || swap_count == 200u)) {
        fprintf(stderr,
                "[BOZ_GL_TEX_SIZE_TOTAL] swap=%u uploads=%u two_by_two=%u "
                "larger=%u other=%u subuploads=%u compressed=%u compressed_unresolved=%u "
                "max_size=%dx%d known_textures=%u\n",
                swap_count, g_boz_tex_uploads, g_boz_tex_size_2x2,
                g_boz_tex_size_large, g_boz_tex_size_other,
                g_boz_tex_sub_uploads, g_boz_tex_compressed_uploads,
                g_boz_tex_compressed_unresolved, g_boz_tex_max_width,
                g_boz_tex_max_height, g_boz_tex_meta_count);
    }
    boz_census_swap(swap_count);
    g_boz_visual_probe_next_swap = swap_count + 1u;
    pace_frame();
    return result;
}

#define HOST(name) {#name, (void *)(uintptr_t)&name}

static const struct host_symbol HOST_SYMBOLS[] = {
    HOST(s3eMallocBase),
    HOST(s3eReallocBase),
    HOST(s3eFreeBase),
    HOST(s3eFileOpen),
    HOST(s3eFileClose),
    HOST(s3eFileRead),
    HOST(s3eFileWrite),
    HOST(s3eFileGetChar),
    HOST(s3eFilePutChar),
    HOST(s3eFileFlush),
    HOST(s3eFileSeek),
    HOST(s3eFileTell),
    HOST(s3eFileGetSize),
    HOST(s3eFileCheckExists),
    HOST(s3eFileGetError),
    HOST(s3eFileGetErrorString),
    HOST(s3eFileOpenFromMemory),
    HOST(s3eFileGetFileInt),
    HOST(s3eFileMakeDirectory),
    HOST(s3eFileDelete),
    HOST(s3eFileRename),
    HOST(s3eFileAddUserFileSys),
    HOST(s3eFileListDirectory),
    HOST(s3eFileListClose),
    HOST(s3eCompressionDecomp),
    HOST(s3eCompressionDecompInit),
    HOST(s3eCompressionDecompRead),
    HOST(s3eCompressionDecompFinal),
    HOST(s3eTimerGetUST),
    HOST(s3eTimerGetMs),
    HOST(s3eTimerGetInt),
    HOST(s3eTimerSetTimer),
    HOST(s3eTimerCancelTimer),
    HOST(s3eTimerGetUTC),
    HOST(s3eTimerGetLocaltimeOffset),
    HOST(s3eDeviceRegister),
    HOST(s3eDeviceUnRegister),
    HOST(s3eDeviceYield),
    HOST(s3eDeviceYieldUntilEvent),
    HOST(s3eDeviceCheckQuitRequest),
    HOST(s3eDeviceCheckPauseRequest),
    HOST(s3eDeviceGetInt),
    HOST(s3eDeviceGetString),
    HOST(s3eDeviceSetInt),
    HOST(s3eDeviceBacklightOn),
    HOST(s3eDeviceRequestQuit),
    HOST(s3eDeviceAbort),
    HOST(s3eDeviceExit),
    HOST(s3eDebugOutputString),
    HOST(s3eDebugPrint),
    HOST(s3eDebugGetInt),
    HOST(s3eDebugIsDebuggerPresent),
    HOST(s3eDebugTraceLine),
    HOST(s3eDebugAssertShow),
    HOST(s3eDebugErrorShow),
    HOST(s3eKeyboardRegister),
    HOST(s3eKeyboardUnRegister),
    HOST(s3eKeyboardUpdate),
    HOST(s3eKeyboardGetState),
    HOST(s3eKeyboardAnyKey),
    HOST(s3eKeyboardGetInt),
    HOST(s3eKeyboardSetInt),
    HOST(s3eKeyboardGetDisplayName),
    HOST(s3eKeyboardClearState),
    HOST(s3ePointerRegister),
    HOST(s3ePointerUnRegister),
    HOST(s3ePointerUpdate),
    HOST(s3ePointerGetInt),
    HOST(s3ePointerSetInt),
    HOST(s3ePointerGetState),
    HOST(s3ePointerGetX),
    HOST(s3ePointerGetY),
    HOST(s3ePointerGetTouchState),
    HOST(s3ePointerGetTouchX),
    HOST(s3ePointerGetTouchY),
    HOST(s3ePointerGetPressure),
    HOST(s3ePointerGetTouchPressure),
    HOST(s3ePointerGetError),
    HOST(s3ePointerGetErrorString),
    HOST(s3eAccelerometerStart),
    HOST(s3eAccelerometerStop),
    HOST(s3eAccelerometerGetX),
    HOST(s3eAccelerometerGetY),
    HOST(s3eAccelerometerGetZ),
    HOST(s3eAccelerometerGetInt),
    HOST(s3eVideoGetInt),
    HOST(s3eVideoPlay),
    HOST(s3eVideoStop),
    HOST(s3eVideoResume),
    HOST(s3eAudioIsPlaying),
    HOST(s3eAudioSetInt),
    HOST(s3eAudioGetInt),
    HOST(s3eAudioPlay),
    HOST(s3eAudioPlayFromBuffer),
    HOST(s3eAudioStop),
    HOST(s3eAudioPause),
    HOST(s3eAudioResume),
    HOST(s3eAudioRegister),
    HOST(s3eSoundGetFreeChannel),
    HOST(s3eSoundSetInt),
    HOST(s3eSoundGetInt),
    HOST(s3eSoundChannelRegister),
    HOST(s3eSoundChannelUnRegister),
    HOST(s3eSoundChannelPlay),
    HOST(s3eSoundChannelStop),
    HOST(s3eSoundChannelPause),
    HOST(s3eSoundChannelResume),
    HOST(s3eSoundChannelSetInt),
    HOST(s3eSoundChannelGetInt),
    HOST(s3eInetHtonl),
    HOST(s3eInetNtohl),
    HOST(s3eInetHtons),
    HOST(s3eInetNtohs),
    HOST(s3eInetAton),
    HOST(s3eInetNtoa),
    HOST(s3eInetToString),
    HOST(s3eInetLookup),
    HOST(s3eInetLookupCancel),
    HOST(s3eSocketCreate),
    HOST(s3eSocketClose),
    HOST(s3eSocketBind),
    HOST(s3eSocketListen),
    HOST(s3eSocketAccept),
    HOST(s3eSocketConnect),
    HOST(s3eSocketSend),
    HOST(s3eSocketSendTo),
    HOST(s3eSocketRecv),
    HOST(s3eSocketRecvFrom),
    HOST(s3eSocketReadable),
    HOST(s3eSocketWritable),
    HOST(s3eSocketGetInt),
    HOST(s3eSocketGetError),
    HOST(s3eSocketGetString),
    HOST(s3eSocketGetLocalName),
    HOST(s3eSocketGetPeerName),
    HOST(s3eMemoryGetInt),
    HOST(s3eMemorySetInt),
    HOST(s3eMemorySetUserMemMgr),
    HOST(s3eMemoryGetUserMemMgr),
    HOST(s3eMemoryHeapCreate),
    HOST(s3eMemoryHeapDestroy),
    HOST(s3eMemoryHeapAddress),
    HOST(s3eMemoryGetError),
    HOST(s3eMemoryGetErrorString),
    HOST(s3eSurfaceRegister),
    HOST(s3eSurfaceUnRegister),
    HOST(s3eSurfaceGetInt),
    HOST(s3eSurfacePtr),
    HOST(s3eSurfaceSetup),
    HOST(s3eSurfaceShow),
    HOST(s3eGLRegister),
    HOST(s3eGLUnRegister),
    HOST(s3eGLGetInt),
    HOST(s3eGLGetNativeWindow),
    HOST(s3eConfigGetInt),
    HOST(s3eConfigGetString),
    HOST(s3eExtGetHash),
};

#define WRAPPED(name) {#name, (void *)(uintptr_t)&host_##name}

static const struct host_symbol WRAPPED_SYMBOLS[] = {
    WRAPPED(glAlphaFunc),
    WRAPPED(glActiveTexture),
    WRAPPED(glBindTexture),
    WRAPPED(glBindFramebuffer),
    WRAPPED(glBindFramebufferOES),
    WRAPPED(glBlendColor),
    WRAPPED(glClear),
    WRAPPED(glClearColor),
    WRAPPED(glClearDepthf),
    WRAPPED(glClearDepthfOES),
    WRAPPED(glColor4f),
    WRAPPED(glCompressedTexImage2D),
    WRAPPED(glCompressedTexSubImage2D),
    WRAPPED(glCopyTexImage2D),
    WRAPPED(glCopyTexSubImage2D),
    WRAPPED(glCreateProgram),
    WRAPPED(glDepthRangef),
    WRAPPED(glDepthRangefOES),
    WRAPPED(glDrawArrays),
    WRAPPED(glDrawElements),
    WRAPPED(glDrawTexfOES),
    WRAPPED(glFogf),
    WRAPPED(glFrustumf),
    WRAPPED(glFrustumfOES),
    WRAPPED(glGetIntegerv),
    WRAPPED(glLightModelf),
    WRAPPED(glLightf),
    WRAPPED(glLineWidth),
    WRAPPED(glLinkProgram),
    WRAPPED(glMaterialf),
    WRAPPED(glMultiTexCoord4f),
    WRAPPED(glNormal3f),
    WRAPPED(glOrthof),
    WRAPPED(glOrthofOES),
    WRAPPED(glPointSize),
    WRAPPED(glPolygonOffset),
    WRAPPED(glReadPixels),
    WRAPPED(glRotatef),
    WRAPPED(glScalef),
    WRAPPED(glScissor),
    WRAPPED(glTexEnvf),
    WRAPPED(glTexImage2D),
    WRAPPED(glTexSubImage2D),
    WRAPPED(glTexGenfOES),
    WRAPPED(glTranslatef),
    WRAPPED(glUniform1f),
    WRAPPED(glUniform4f),
    WRAPPED(glUseProgram),
    WRAPPED(glViewport),
    WRAPPED(eglGetProcAddress),
    WRAPPED(eglSwapBuffers),
};

static void *resolve_wrapped_host_proc(const char *symbol) {
    for (size_t i = 0; i < sizeof(WRAPPED_SYMBOLS) / sizeof(WRAPPED_SYMBOLS[0]); ++i) {
        if (strcmp(symbol, WRAPPED_SYMBOLS[i].name) == 0) {
            return WRAPPED_SYMBOLS[i].fn;
        }
    }
    return NULL;
}

void *s3e_host_resolve(const char *symbol) {
    void *wrapped = resolve_wrapped_host_proc(symbol);
    if (wrapped) {
        return wrapped;
    }
    if (strncmp(symbol, "egl", 3) == 0) {
        void *addr = egl_backend_resolve(symbol);
        if (!addr) {
            addr = lookup_egl(symbol);
        }
        return addr ? addr : make_stub(symbol);
    }
    if (strncmp(symbol, "gl", 2) == 0) {
        void *addr = lookup_gl(symbol);
        return addr ? addr : make_stub(symbol);
    }
    for (size_t i = 0; i < sizeof(HOST_SYMBOLS) / sizeof(HOST_SYMBOLS[0]); ++i) {
        if (strcmp(symbol, HOST_SYMBOLS[i].name) == 0) {
            return HOST_SYMBOLS[i].fn;
        }
    }
    if (strncmp(symbol, "s3e", 3) == 0) {
        return make_stub(symbol);
    }
    return NULL;
}
