/* Regression: discover real console.bin from a loader-format DTRZ archive.
 * Synthetic archive fixture, no copyrighted game bytes.
 */
#include "s3e_host_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char g_root[1024];
struct dtrz_index g_dtrz;
struct memory_file *g_memory_files;

void codboz_hide_virtual_stick_artwork(const char *name, uint8_t *data, size_t size) {
    (void)name;
    (void)data;
    (void)size;
}

static void put_u16(FILE *f, uint16_t v) {
    assert(fputc(v & 255, f) != EOF);
    assert(fputc((v >> 8) & 255, f) != EOF);
}

static void put_u32(FILE *f, uint32_t v) {
    put_u16(f, v & 0xffff);
    put_u16(f, (v >> 16) & 0xffff);
}

static void make_loader_archive(const char *path) {
    FILE *f = fopen(path, "wb");
    assert(f);
    /* 9-byte header, one file, one group (group_count - 1 = 0). */
    assert(fwrite("DTRZ", 1, 4, f) == 4);
    put_u16(f, 1);
    put_u16(f, 1);
    assert(fputc(0, f) != EOF);
    assert(fwrite("console.bin", 1, sizeof("console.bin"), f) == sizeof("console.bin"));
    put_u32(f, 1);                 /* marker */
    uint8_t six_bytes[6] = {0};  /* per-file group refs */
    assert(fwrite(six_bytes, 1, 6, f) == 6);
    const uint32_t payload_offset = 9 + sizeof("console.bin") + 4 + 6 + 16;
    put_u32(f, payload_offset);
    put_u32(f, 6);
    put_u32(f, 6);
    put_u32(f, 256);
    assert(ftell(f) == (long)payload_offset);
    assert(fwrite("VALID!", 1, 6, f) == 6);
    assert(fclose(f) == 0);
}

int main(void) {
    char dir[] = "/tmp/boz-dtrz-test-XXXXXX";
    assert(mkdtemp(dir));
    snprintf(g_root, sizeof(g_root), "%s", dir);
    char asset_dir[1200];
    char archive_path[1200];
    snprintf(asset_dir, sizeof(asset_dir), "%s/assets", dir);
    assert(mkdir(asset_dir, 0700) == 0);
    assert(strlen(asset_dir) + strlen("/blackops_loader.dz") + 1 < sizeof(archive_path));
    strcpy(archive_path, asset_dir);
    strcat(archive_path, "/blackops_loader.dz");
    make_loader_archive(archive_path);

    assert(s3eFileCheckExists("console.bin") == 1);
    assert(s3eFileCheckExists("data-gles1/console.bin") == 1);
    /* Loader archive must not masquerade as full game texture archive. */
    assert(s3eFileCheckExists("blackops_gles1.dz") == 0);
    void *file = s3eFileOpen("data-gles1/console.bin", "rb");
    assert(file);
    assert(s3eFileGetSize(file) == 6);
    char contents[7] = {0};
    assert(s3eFileRead(contents, 1, 6, file) == 6);
    assert(strcmp(contents, "VALID!") == 0);
    assert(s3eFileClose(file) == 0);
    assert(unlink(archive_path) == 0);
    assert(rmdir(asset_dir) == 0);
    assert(rmdir(dir) == 0);
    puts("DTRZ loader console.bin: PASS");
    return 0;
}
