#include <string.h>

#include "certutils.h"

CU_STATUS cu_read_cert(const char *filename, CU_CERT **cert) {
    CU_STATUS rc = CU_OK;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open cert file for reading.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!*cert) {
        fprintf(stderr, "Failed to read cert from file.\n");
        rc = CU_OSSL_ERR;
        goto cleanup;
    }

cleanup:
    if (fp) {
        fclose(fp);
    }

    return rc;
}

CU_STATUS cu_read_crl(const char *filename, CU_CRL **crl) {
    CU_STATUS rc = CU_OK;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open crl file for reading.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
    if (!*crl) {
        fprintf(stderr, "Failed to read crl from file.\n");
        rc = CU_OSSL_ERR;
        goto cleanup;
    }

cleanup:
    if (fp) {
        fclose(fp);
    }

    return rc;
}

CU_STATUS cu_read_file(const char *filename, char **buf, size_t *buf_len) {
    CU_STATUS rc = CU_OK;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file for reading.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek to the end of the file.\n");
        rc = CU_MEM_ERR;
        goto cleanup;
    }

    long bufsize = ftell(fp);
    if (bufsize == -1) {
        fprintf(stderr, "Failed to get file size.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    *buf = malloc(sizeof(char) * ((unsigned long)bufsize + 1));
    if (!*buf) {
        fprintf(stderr, "Failed to allocate memory.\n");
        rc = CU_MEM_ERR;
        goto cleanup;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to the beginning of the file.\n");
        rc = CU_MEM_ERR;
        goto cleanup;
    }

    *buf_len = fread(*buf, sizeof(char), (size_t)bufsize, fp);
    if (*buf_len != (size_t)bufsize) {
        fprintf(stderr, "Failed to read file.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    } else {
        // Strip trailing carriage returns and new lines
        char *pos = &(*buf)[*buf_len];
        *pos = '\0';
        pos--;
        while (*pos == '\r' || *pos == '\n') {
            *pos = '\0';
            pos--;
            (*buf_len)--;
        }
        *buf = realloc(*buf, *buf_len + 1);
    }

cleanup:
    if (fp) {
        fclose(fp);
    }

    if (rc != CU_OK) {
        free(*buf);
        *buf = NULL;
    }

    return rc;
}
