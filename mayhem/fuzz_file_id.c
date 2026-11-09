/* Fuzzes FastDFS's file-id / remote-filename helpers: file-id decoding (fdfs_get_file_info_ex1),
 * data-filename validation, slave-filename generation and the HTTP anti-steal token helpers.
 * Input: byte 0 selects the operation, the rest is NUL-terminated text (split at '\n' where an
 * operation needs several strings). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "quiet_log.h"
#include "fdfs_global.h"
#include "fdfs_http_shared.h"
#include "storage_client.h"
#include "storage_client1.h"

#define MAX_TEXT 512

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    mayhem_quiet_log_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char text[MAX_TEXT + 1];
    char *part2;
    char *part3;
    size_t len;

    if (size < 1 || size > MAX_TEXT) {
        return -1;
    }
    len = size - 1;
    memcpy(text, data + 1, len);
    text[len] = '\0';

    part2 = strchr(text, '\n');
    if (part2 != NULL) {
        *part2++ = '\0';
        part3 = strchr(part2, '\n');
        if (part3 != NULL) {
            *part3++ = '\0';
        }
    } else {
        part3 = NULL;
    }

    switch (data[0] & 3) {
    case 0: {
        FDFSFileInfo info;
        fdfs_get_file_info_ex1(text, false, &info, 0);
        break;
    }
    case 1:
        fdfs_check_data_filename(text, (int)strlen(text));
        break;
    case 2: {
        char out[MAX_TEXT + 16];
        int out_len = 0;
        if (part2 == NULL || part3 == NULL) {
            return -1;
        }
        fdfs_gen_slave_filename(text, part2, part3, out, &out_len);
        break;
    }
    default: {
        BufferInfo secret;
        char token[64];
        int ext_len = 0;
        if (part2 == NULL) {
            return -1;
        }
        fdfs_http_get_file_extension(text, (int)strlen(text), &ext_len);
        secret.buff = part2;
        secret.length = (int)strlen(part2);
        if (fdfs_http_gen_token(&secret, text, 1700000000, token) == 0) {
            fdfs_http_check_token(&secret, text, 1700000000, token, 3600);
            if (part3 != NULL) {
                fdfs_http_check_token(&secret, text, 0, part3, 3600);
            }
        }
        break;
    }
    }
    return 0;
}
