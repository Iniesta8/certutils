#include <string.h>

#include "certutils.h"
#include "type.h"

static int create_search_patterns(const char *var_text,
                                  struct search_patterns **sp) {
    *sp = (struct search_patterns *)malloc(sizeof(struct search_patterns));
    if (!*sp) {
        fprintf(stderr, "Failed to allocate memory for search patterns.\n");
        return -1;
    }

    (*sp)->begin.pattern_len = SP_PEM_HEADER_BASE_LEN + strlen(var_text);
    strcpy((*sp)->begin.pattern, SP_PEM_BEGIN);
    strncat((*sp)->begin.pattern, var_text, strlen(var_text));
    strcat((*sp)->begin.pattern, SP_PEM_DASHES);

    (*sp)->end.pattern_len = SP_PEM_FOOTER_BASE_LEN + strlen(var_text);
    strcpy((*sp)->end.pattern, SP_PEM_END);
    strncat((*sp)->end.pattern, var_text, strlen(var_text));
    strcat((*sp)->end.pattern, SP_PEM_DASHES);

    return 0;
}

static inline void free_search_patterns(struct search_patterns **sp) {
    free(*sp);
    *sp = NULL;
}

static const char *type_texts[] = {
    CU_FTYPE_CERT_TEXT,   CU_FTYPE_X509_CERT_TEXT,  CU_FTYPE_TRUSTED_CERT_TEXT,
    CU_FTYPE_CRL_TEXT,    CU_FTYPE_CSR_TEXT,        CU_FTYPE_NEW_CSR_TEXT,
    CU_FTYPE_PKCS7_TEXT,  CU_FTYPE_PRIVKEY_TEXT,    CU_FTYPE_RSA_PRIVKEY_TEXT,
    CU_FTYPE_PUBKEY_TEXT, CU_FTYPE_RSA_PUBKEY_TEXT, NULL};

static CU_FILETYPE str2type(const char *str) {
    if ((strcmp(str, CU_FTYPE_CERT_TEXT) == 0) ||
        (strcmp(str, CU_FTYPE_X509_CERT_TEXT) == 0) ||
        (strcmp(str, CU_FTYPE_TRUSTED_CERT_TEXT) == 0)) {
        return CU_FTYPE_CERT;
    }
    if (strcmp(str, CU_FTYPE_CRL_TEXT) == 0) {
        return CU_FTYPE_CRL;
    }
    if (strcmp(str, CU_FTYPE_CSR_TEXT) == 0) {
        return CU_FTYPE_CSR;
    }
    if (strcmp(str, CU_FTYPE_NEW_CSR_TEXT) == 0) {
        return CU_FTYPE_NEW_CSR;
    }
    if (strcmp(str, CU_FTYPE_PKCS7_TEXT) == 0) {
        return CU_FTYPE_PKCS7;
    }
    if ((strcmp(str, CU_FTYPE_RSA_PRIVKEY_TEXT) == 0) ||
        (strcmp(str, CU_FTYPE_PRIVKEY_TEXT) == 0)) {
        return CU_FTYPE_PRIVKEY;
    }
    if ((strcmp(str, CU_FTYPE_PUBKEY_TEXT) == 0) ||
        (strcmp(str, CU_FTYPE_RSA_PUBKEY_TEXT) == 0)) {
        return CU_FTYPE_PUBKEY;
    }
    return CU_FTYPE_UNKNOWN;
}

CU_FILETYPE cu_get_file_type(const char *filename) {
    CU_FILETYPE rc = CU_FTYPE_UNKNOWN;
    CU_STATUS status = CU_UNKNOWN_ERR;
    struct search_patterns *sp = NULL;
    char *buf = NULL;
    size_t buf_len = 0;

    status = cu_read_file(filename, &buf, &buf_len);
    if (CU_OK != status) {
        fprintf(stderr, "Failed to read file into memory.\n");
        goto cleanup;
    }

    const char **p = type_texts;
    while (*p) {
        int res = create_search_patterns(*p, &sp);
        if (res == -1) {
            rc = CU_FTYPE_UNKNOWN;
            goto cleanup;
        }
        if ((strncmp(&buf[0], sp->begin.pattern, sp->begin.pattern_len) == 0) &&
            (strncmp(&buf[strlen(buf) - sp->end.pattern_len], sp->end.pattern,
                     sp->end.pattern_len) == 0)) {
            rc = str2type(*p);
            goto cleanup;
        }
        free_search_patterns(&sp);
        p++;
    }
cleanup:
    free_search_patterns(&sp);
    free(buf);
    buf = NULL;

    return rc;
}
