#include "s3e_host_internal.h"

#include <assert.h>

static const unsigned char compressed_small[] = {
    0x78,0xda,0x73,0xf2,0x8f,0x52,0x08,0xf0,0x73,0x57,0x70,0x71,0x75,
    0xf6,0x77,0x71,0x0d,0x52,0x08,0x71,0x0d,0x0e,0x51,0x70,0x71,0x0c,
    0x71,0x04,0x00,0x56,0x34,0x06,0xa1
};
static const char expected_small[] = "BOZ PNG DECODER TEST DATA";

static void test_output_owned_by_host(void) {
    void *out = NULL;
    uint32_t len = 0;
    assert(s3eCompressionDecomp(compressed_small, sizeof(compressed_small),
                                &out, &len, 2) == 0);
    assert(out && len == sizeof(expected_small) - 1u);
    assert(memcmp(out, expected_small, len) == 0);
    free(out);
}

static void test_caller_owned_destination(void) {
    char data[64];
    memset(data, 0xcc, sizeof(data));
    void *out = data;
    uint32_t len = sizeof(data);
    assert(s3eCompressionDecomp(compressed_small, sizeof(compressed_small),
                                &out, &len, 2) == 0);
    assert(out == data && len == sizeof(expected_small)-1u);
    assert(memcmp(data, expected_small, len) == 0);
}

static void test_fail_closed(void) {
    char data[64];
    memset(data, 0xcc, sizeof(data));
    void *out = data;
    uint32_t len = 5;
    assert(s3eCompressionDecomp(compressed_small, sizeof(compressed_small),
                                &out, &len, 2) != 0);
    assert(out == data && len == 5 && (unsigned char)data[0] == 0xcc);
    len = sizeof(data);
    assert(s3eCompressionDecomp(compressed_small, sizeof(compressed_small),
                                &out, &len, 1) != 0);
    assert(out == data && len == sizeof(data));
    static const unsigned char invalid_data[] = {0x78,0x9c,0xff,0xff};
    assert(s3eCompressionDecomp(invalid_data, sizeof(invalid_data),
                                &out, &len, 2) != 0);
    assert(out == data && len == sizeof(data));
    assert(s3eCompressionDecomp(NULL, 0, &out, &len, 2) != 0);
}

static void test_large_growing_output(void) {
    void *libz = dlopen("libz.so.1", RTLD_NOW | RTLD_LOCAL);
    assert(libz != NULL);
    typedef int (*compress2_fn)(unsigned char *, unsigned long *,
                                const unsigned char *, unsigned long, int);
    compress2_fn compress2_ptr = (compress2_fn)dlsym(libz, "compress2");
    assert(compress2_ptr != NULL);
    const size_t raw_size = 200000u;
    unsigned char *raw = malloc(raw_size);
    unsigned char *compressed = malloc(raw_size + 100u);
    assert(raw && compressed);
    for (size_t i=0; i<raw_size; ++i)
        raw[i] = (unsigned char)"BOZ_"[i % 4u];
    unsigned long compressed_len = raw_size + 100u;
    assert(compress2_ptr(compressed, &compressed_len, raw, raw_size, 9) == 0);
    void *out = NULL;
    uint32_t len = 0;
    assert(s3eCompressionDecomp(compressed, (uint32_t)compressed_len,
                                &out, &len, 2) == 0);
    assert(out && len == raw_size && memcmp(raw, out, raw_size) == 0);
    free(out);
    free(compressed);
    free(raw);
    dlclose(libz);
}

int main(void) {
    test_output_owned_by_host();
    test_caller_owned_destination();
    test_fail_closed();
    test_large_growing_output();
    puts("s3eCompressionDecomp: success, capacity, invalid method, corruption, growth OK");
    return 0;
}
