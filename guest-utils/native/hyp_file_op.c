#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#define MAGIC_GET 0xf113c0e1
#define MAGIC_PUT 0xf113c0e2
#define MAGIC_GET_PERM 0xf113c0e3
#define MAGIC_GETSIZE 0xf113c0e4
#include "portal_call.h"

#define MAX_MALLOC_SIZE (32 * 1024 * 1024) // 32MB max allocation
#define MALLOC_SIZE MAX_MALLOC_SIZE
#define CHUNK_SIZE MALLOC_SIZE

void require(bool cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "hyp_file_op: error: %s\n", msg);
        exit(1);
    }
}

int verbose = 0;

void log_info(const char *msg) {
    if (verbose) fprintf(stderr, "[hyp_file_op] %s\n", msg);
}
void log_fmt(const char *fmt, ...) {
    if (!verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[hyp_file_op] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

int main(int argc, char **argv) {
    int arg_offset = 1;
    if (argc > 1 && strcmp(argv[1], "--verbose") == 0) {
        verbose = 1;
        arg_offset = 2;
    }
    if (argc - arg_offset < 2) {
        fprintf(stderr, "Usage: %s [--verbose] <get|put> <path> [localfile]\n", argv[0]);
        return 1;
    }
    const char *op = argv[arg_offset];
    const char *path_arg = argv[arg_offset + 1];
    size_t path_len = strlen(path_arg) + 1;
    char *path = malloc(path_len);
    require(path, "malloc failed for path");
    strcpy(path, path_arg);
    if (strcmp(op, "get") == 0) {
        log_fmt("Requesting file size for '%s'", path);
        long file_size = portal_callN(MAGIC_GETSIZE, 1, (uint64_t)path);
        if (file_size == -1) {
            fprintf(stderr, "hyp_file_op: error: file '%s' does not exist\n", path);
            free(path);
            return 2;
        }
        log_fmt("File size returned: %ld", file_size);
        require(file_size > 0, "invalid file size returned by portal_callN");
        size_t alloc_size = (size_t)file_size;
        log_fmt("Starting file transfer: '%s', size=%zu", path, alloc_size);
        FILE *out = (argc - arg_offset > 2 && strcmp(argv[arg_offset + 2], "-") != 0) ? fopen(argv[arg_offset + 2], "wb") : stdout;
        require(out, "failed to open output file");

        uint8_t *buffer = malloc(MAX_MALLOC_SIZE);
        require(buffer, "malloc failed");
        size_t total_read = 0;
        int done = 0;
        int chunk_idx = 0;
        while (!done && total_read < alloc_size) {
            size_t chunk_offset = chunk_idx * CHUNK_SIZE;
            size_t chunk_size = CHUNK_SIZE;
            if (chunk_offset + chunk_size > alloc_size)
                chunk_size = alloc_size - chunk_offset;
            if (chunk_size > MAX_MALLOC_SIZE) chunk_size = MAX_MALLOC_SIZE;
            log_fmt("Requesting chunk %d: offset=%zu, size=%zu", chunk_idx, chunk_offset, chunk_size);
            log_fmt("portal_callN: MAGIC_GET, path='%s', offset=%zu, size=%zu, buffer=%p", path, chunk_offset, chunk_size, buffer);
            int ret = portal_call4(MAGIC_GET, (uint64_t)path, chunk_offset, chunk_size, (uint64_t)buffer);
            log_fmt("Chunk %d: portal_callN returned %d", chunk_idx, ret);
            if (ret < 0) {
                log_fmt("portal_callN failed at chunk %d", chunk_idx);
                free(buffer);
                free(path);
                if (out != stdout) fclose(out);
                return 2;
            }
            if (ret == 0) {
                log_fmt("Warning: chunk %d returned 0 bytes", chunk_idx);
                done = 1;
            } else {
                size_t written = fwrite(buffer, 1, ret, out);
                log_fmt("Chunk %d: transferred %d bytes, written %zu bytes", chunk_idx, ret, written);
                if (written != (size_t)ret) {
                    log_fmt("Warning: fwrite wrote less than expected (%zu/%d)", written, ret);
                }
                total_read += ret;
                chunk_idx++;
                if (ret < chunk_size) done = 1;
            }
        }
        free(buffer);
        if (total_read == 0) {
            log_fmt("Warning: total_read is 0 after file transfer");
        }
        log_fmt("Requesting file permissions for '%s'", path);
        long file_mode = portal_call1(MAGIC_GET_PERM, (uint64_t)path);
        log_fmt("File mode returned: %ld", file_mode);
        if (out != stdout) {
            fclose(out);
            if (file_mode > 0) {
                log_fmt("Setting permissions on '%s' to %o", argv[arg_offset + 2], (mode_t)file_mode);
                chmod(argv[arg_offset + 2], (mode_t)file_mode);
            }
        }
        log_fmt("File transfer complete: '%s', total_read=%zu", path, total_read);
        free(path);
        return 0;
    } else if (strcmp(op, "put") == 0) {
        // put <source> <dest>
        require(argc - arg_offset >= 3, "put requires source and dest arguments");
        const char *local_path = argv[arg_offset + 1];
        const char *remote_path = argv[arg_offset + 2];
        log_fmt("Starting file upload: '%s' to remote '%s'", local_path, remote_path);
        FILE *in = strcmp(local_path, "-") == 0 ? stdin : fopen(local_path, "rb");
        char errbuf[256];
        if (strcmp(local_path, "-") == 0) {
            snprintf(errbuf, sizeof(errbuf), "failed to open stdin");
        } else {
            snprintf(errbuf, sizeof(errbuf), "failed to open input file: %s", local_path);
        }
        require(in, errbuf);

        size_t file_size = 0;
        uint8_t *buffer = NULL;
        if (in == stdin) {
            buffer = malloc(MAX_MALLOC_SIZE);
            require(buffer, "malloc failed");
            size_t total_sent = 0;
            int chunk_idx = 0;
            while (1) {
                size_t chunk_size = fread(buffer, 1, MAX_MALLOC_SIZE, stdin);
                if (chunk_size == 0) break;
                log_fmt("Sending chunk %d: offset=%zu, size=%zu", chunk_idx, total_sent, chunk_size);
                int ret = portal_call4(MAGIC_PUT, (uint64_t)remote_path, total_sent, chunk_size, (uint64_t)buffer);
                if (ret < 0) {
                    log_fmt("portal_callN failed at chunk %d", chunk_idx);
                    free(buffer);
                    free(path);
                    return 2;
                }
                log_fmt("Chunk %d: sent %d bytes", chunk_idx, ret);
                total_sent += ret;
                chunk_idx++;
                if ((size_t)ret < chunk_size) break;
            }
            log_fmt("File upload complete: '%s', total_sent=%zu", path, total_sent);
            free(buffer);
            free(path);
            return 0;
        } else {
            fseek(in, 0, SEEK_END);
            file_size = ftell(in);
            fseek(in, 0, SEEK_SET);
            buffer = malloc(file_size);
            require(buffer, "malloc failed");
            fread(buffer, 1, file_size, in);
            fclose(in);
            log_fmt("Uploading file: '%s', size=%zu", path, file_size);
            size_t total_sent = 0;
            int chunk_idx = 0;
            while (total_sent < file_size) {
                size_t chunk_offset = chunk_idx * CHUNK_SIZE;
                size_t chunk_size = CHUNK_SIZE;
                if (chunk_offset + chunk_size > file_size)
                    chunk_size = file_size - chunk_offset;
                log_fmt("Sending chunk %d: offset=%zu, size=%zu", chunk_idx, chunk_offset, chunk_size);
                int ret = portal_call4(MAGIC_PUT, (uint64_t)remote_path, chunk_offset, chunk_size, (uint64_t)(buffer + chunk_offset));
                if (ret < 0) {
                    log_fmt("portal_callN failed at chunk %d", chunk_idx);
                    free(buffer);
                    free(path);
                    return 2;
                }
                log_fmt("Chunk %d: sent %d bytes", chunk_idx, ret);
                total_sent += ret;
                chunk_idx++;
                if (ret < chunk_size) break;
            }
            log_fmt("File upload complete: '%s', total_sent=%zu", path, total_sent);
            free(buffer);
            free(path);
            return 0;
        }
    } else {
        free(path);
        fprintf(stderr, "Unknown operation: %s\n", op);
        return 1;
    }
}