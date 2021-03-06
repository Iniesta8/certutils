#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certutils.h"
#include "openssl_mock.h"

#include <CppUTestExt/MockSupport.h>

char err[256];

X509_NAME *X509_CRL_get_issuer(const X509_CRL *x) {
    mock().actualCall(__FUNCTION__).withParameterOfType("X509 *", "x", x);

    (void)x;
    char *crl_issuer = NULL;
    size_t crl_issuer_size = 0;

    crl_issuer_size = strlen(MOCK_CRL_ISSUER_CN) + strlen(MOCK_CRL_ISSUER_C) +
                      strlen(MOCK_CRL_ISSUER_O) + strlen(MOCK_CRL_ISSUER_OU) +
                      strlen(MOCK_CRL_ISSUER_ST) + strlen(MOCK_CRL_ISSUER_L);
    crl_issuer_size += strlen("\\CN=") + strlen("\\C=") + strlen("\\O=") +
                       strlen("\\OU=") + strlen("\\ST=") + strlen("\\L=");
    crl_issuer_size += strlen(RAW_DATA_PREFIX) + 1;

    // Code the data into the X509_NAME struct
    if (NULL == (crl_issuer = (char *)calloc(1, crl_issuer_size))) {
        snprintf(err, sizeof(err), "%s",
                 "Could not allocate memory for X509_NAME structure in "
                 "X509_get_issuer_name mock");
        return NULL;
    }
    snprintf(crl_issuer, crl_issuer_size,
             "%s\\CN=%s\\C=%s\\O=%s\\OU=%s\\ST=%s\\L=%s", RAW_DATA_PREFIX,
             MOCK_CRL_ISSUER_CN, MOCK_CRL_ISSUER_C, MOCK_CRL_ISSUER_O,
             MOCK_CRL_ISSUER_OU, MOCK_CRL_ISSUER_ST, MOCK_CRL_ISSUER_L);
    return (X509_NAME *)crl_issuer;
}

X509_NAME *X509_get_issuer_name(const X509 *x) {
    mock().actualCall(__FUNCTION__).withParameterOfType("X509 *", "x", x);

    (void)x;
    char *issuer = NULL;
    size_t issuer_size = 0;

    issuer_size = strlen(MOCK_ISSUER_CN) + strlen(MOCK_ISSUER_C) +
                  strlen(MOCK_ISSUER_O) + strlen(MOCK_ISSUER_OU) +
                  strlen(MOCK_ISSUER_ST) + strlen(MOCK_ISSUER_L);
    issuer_size += strlen("\\CN=") + strlen("\\C=") + strlen("\\O=") +
                   strlen("\\OU=") + strlen("\\ST=") + strlen("\\L=");
    issuer_size += strlen(RAW_DATA_PREFIX) + 1;

    // Code the data into the X509_NAME struct
    if (NULL == (issuer = (char *)calloc(1, issuer_size))) {
        snprintf(err, sizeof(err), "%s",
                 "Could not allocate memory for X509_NAME structure in "
                 "X509_get_issuer_name mock");
        return NULL;
    }
    snprintf(issuer, issuer_size, "%s\\CN=%s\\C=%s\\O=%s\\OU=%s\\ST=%s\\L=%s",
             RAW_DATA_PREFIX, MOCK_ISSUER_CN, MOCK_ISSUER_C, MOCK_ISSUER_O,
             MOCK_ISSUER_OU, MOCK_ISSUER_ST, MOCK_ISSUER_L);
    return (X509_NAME *)issuer;
}

X509_NAME *X509_get_subject_name(const X509 *x) {
    mock().actualCall(__FUNCTION__).withParameterOfType("X509 *", "x", x);

    (void)x;
    char *subject = NULL;
    size_t subject_size = 0;

    subject_size = strlen(MOCK_CN) + strlen(MOCK_C) + strlen(MOCK_O) +
                   strlen(MOCK_OU) + strlen(MOCK_ST) + strlen(MOCK_L);
    subject_size += strlen("\\CN=") + strlen("\\C=") + strlen("\\O=") +
                    strlen("\\OU=") + strlen("\\ST=") + strlen("\\L=");
    subject_size += strlen(RAW_DATA_PREFIX) + 1;

    // Code the data into the X509_NAME struct
    if (NULL == (subject = (char *)calloc(1, subject_size))) {
        snprintf(err, sizeof(err), "%s",
                 "Could not allocate memory for X509_NAME structure in "
                 "X509_get_subject_name mock");
        return NULL;
    }
    snprintf(subject, subject_size, "%s\\CN=%s\\C=%s\\O=%s\\OU=%s\\ST=%s\\L=%s",
             RAW_DATA_PREFIX, MOCK_CN, MOCK_C, MOCK_O, MOCK_OU, MOCK_ST,
             MOCK_L);
    return (X509_NAME *)subject;
}

char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size) {
    mock()
        .actualCall(__FUNCTION__)
        .withParameterOfType("X509_NAME *", "a", a)
        .withParameterOfType("char *", "buf", buf)
        .withParameter("size", size);

    // We coded the data to return here into the X509_NAME struct
    // Have to remove the RAW_DATA_PREFIX
    char *dest_buf = NULL;
    size_t dest_buf_size = 0;
    if (buf) {
        dest_buf_size = (size_t)size;
        memset(buf, '\0', dest_buf_size);
        dest_buf = buf;
    } else {
        dest_buf_size = strlen((const char *)a) + 1 - strlen(RAW_DATA_PREFIX);
        if (NULL == (dest_buf = (char *)calloc(1, dest_buf_size)))
            return NULL;
    }

    // Do not handle non-ASCII characters in test
    snprintf(dest_buf, dest_buf_size, "%s",
             (const char *)a + strlen(RAW_DATA_PREFIX));
    return dest_buf;
}

const ASN1_INTEGER *X509_get0_serialNumber(const X509 *cert) {
    mock().actualCall(__FUNCTION__).withParameterOfType("X509 *", "cert", cert);

    (void)cert;
    char *sn = NULL;
    size_t sn_len = 0;

    if (!cert)
        return NULL;

    sn_len += strlen(MOCK_SN);
    sn_len += strlen(MOCK_ASN1_PREFIX) + 1;

    if (NULL == (sn = (char *)calloc(1, sn_len)))
        return NULL;

    // Encode the serial number as ASN1_<SN>
    snprintf(sn, sn_len, "%s%s", MOCK_ASN1_PREFIX, MOCK_SN);
    return (const ASN1_INTEGER *)sn;
}

BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn) {
    mock()
        .actualCall(__FUNCTION__)
        .withParameterOfType("ASN1_INTEGER *", "ai", ai)
        .withParameterOfType("BIGNUM *", "bn", bn);

    // Our BIGNUM is a simple long
    long *dest_bn = (long *)bn;
    const char *start_sn = ((const char *)ai) + strlen(MOCK_ASN1_PREFIX);

    if (!dest_bn) {
        if (NULL == (dest_bn = (long *)calloc(sizeof(long), 1)))
            return NULL;
    }

    *dest_bn = strtol(start_sn, NULL, 10);
    return (BIGNUM *)dest_bn;
}

char *BN_bn2hex(const BIGNUM *a) {
    mock().actualCall(__FUNCTION__).withParameterOfType("BIGNUM *", "a", a);

    char *dest = NULL;
    size_t dest_len = sizeof(long) * 2 + 1;

    if (NULL == (dest = (char *)calloc(1, dest_len)))
        return NULL;

    snprintf(dest, dest_len, "%lx", *(long *)a);
    return dest;
}

void BN_free(BIGNUM *a) {
    mock().actualCall(__FUNCTION__).withParameterOfType("BIGNUM *", "a", a);

    free(a);
}

long BIO_ctrl(BIO *bp,int cmd,long larg,void *parg) {
    return 0L;
}

int BIO_puts(BIO *b, const char *buf) {
    return 0;
}

const BIO_METHOD* BIO_s_mem() {
    return nullptr;
}

int BIO_printf(BIO *bio, const char *format, ...) {
    return 0;
}

int BIO_free(BIO *a) {
    return 0;
}

BIO* BIO_new(const BIO_METHOD *type) {
    return nullptr;
};

int X509_digest(const X509 *data, const EVP_MD *type,
        unsigned char *md, unsigned int *len) {
    return 0;
}
void X509_free(X509 *a) {
}

X509_EXTENSION *X509_get_ext(const X509 *x, int loc) {
    return nullptr;
}

const ASN1_TIME * X509_get0_notBefore(const X509 *x) {
    return nullptr;
}

const ASN1_TIME *X509_get0_notAfter(const X509 *x) {
    return nullptr;
}

const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl) {
    return nullptr;
}

const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl) {
    return nullptr;
}

int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos) {
    return 0;
}

void X509_CRL_free(X509_CRL *a) {
}

int EVP_MD_type(const EVP_MD *md) {
    return 0;
}

const EVP_MD *EVP_sha1() {
    return nullptr;
}

extern "C" int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent) {
    return 0;
}

const char *OBJ_nid2sn(int n) {
    return nullptr;
}

int PEM_write_X509(FILE *fp, X509 *x) {
    return 0;
}

X509_CRL *PEM_read_X509_CRL(FILE *fp, X509_CRL **x, pem_password_cb *cb, void *u) {
    return nullptr;
}

X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u) {
    return nullptr;
}

X509 *d2i_X509_fp(FILE *fp, X509 **x) {
    return nullptr;
}

int i2d_X509_fp(FILE *fp, X509 *x) {
    return 0;
}

int ASN1_TIME_print(BIO *b, const ASN1_TIME *s) {
    return 0;
}
