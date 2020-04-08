#ifndef TYPE_H
#define TYPE_H

#include <stdlib.h>

#define SP_MAX_LEN 64

#define SP_PEM_BEGIN "-----BEGIN "
#define SP_PEM_BEGIN_LEN strlen(SP_PEM_BEGIN)
#define SP_PEM_END "-----END "
#define SP_PEM_END_LEN strlen(SP_PEM_END)
#define SP_PEM_DASHES "-----"
#define SP_PEM_DASHES_LEN strlen(SP_PEM_DASHES)
#define SP_PEM_HEADER_BASE_LEN (SP_PEM_BEGIN_LEN + SP_PEM_DASHES_LEN)
#define SP_PEM_FOOTER_BASE_LEN (SP_PEM_END_LEN + SP_PEM_DASHES_LEN)

#define CU_FTYPE_CERT_TEXT "CERTIFICATE"
#define CU_FTYPE_X509_CERT_TEXT "X509 CERTIFICATE"
#define CU_FTYPE_TRUSTED_CERT_TEXT "TRUSTED CERTIFICATE"
#define CU_FTYPE_CRL_TEXT "X509 CRL"
#define CU_FTYPE_CSR_TEXT "CERTIFICATE REQUEST"
#define CU_FTYPE_NEW_CSR_TEXT "NEW CERTIFICATE REQUEST"
#define CU_FTYPE_PKCS7_TEXT "PKCS7"
#define CU_FTYPE_PRIVKEY_TEXT "PRIVATE KEY"
#define CU_FTYPE_RSA_PRIVKEY_TEXT "RSA PRIVATE KEY"
#define CU_FTYPE_PUBKEY_TEXT "PUBLIC KEY"
#define CU_FTYPE_RSA_PUBKEY_TEXT "RSA PUBLIC KEY"

struct search_pattern {
    char pattern[SP_MAX_LEN];
    size_t pattern_len;
};

struct search_patterns {
    struct search_pattern begin;
    struct search_pattern end;
};

#endif // TYPE_H
