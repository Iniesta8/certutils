#define __USE_XOPEN
#define _GNU_SOURCE
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "certutils.h"

CU_STATUS cu_cert_get_subject_name(const X509 *cert, char **subject_name) {
    *subject_name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    return CU_OK;
}

CU_STATUS cu_cert_get_issuer_name(const X509 *cert, char **issuer_name) {
    *issuer_name = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    return CU_OK;
}

CU_STATUS cu_crl_get_issuer_name(const X509_CRL *crl, char **issuer_name) {
    *issuer_name = X509_NAME_oneline(X509_CRL_get_issuer(crl), NULL, 0);
    return CU_OK;
}

CU_STATUS cu_cert_get_serial_number(const X509 *cert, char **serial_number) {
    CU_STATUS rc = CU_OK;
    const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
    BIGNUM *bn_serial = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn_serial == NULL) {
        fprintf(stderr, "Failed to parse read serial number.\n");
        return CU_OSSL_ERR;
    }
    *serial_number = BN_bn2hex(bn_serial);
    if (*serial_number == NULL) {
        fprintf(
            stderr,
            "Failed to convert read serial number to hex representation.\n");
        rc = CU_OSSL_ERR;
    }
    BN_free(bn_serial);

    return rc;
}

static int asn1_time_to_buf(const ASN1_TIME *asn1_time, char **time_str) {
    int rc = 0;
    BUF_MEM *bptr = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!ASN1_TIME_print(bio, asn1_time)) {
        fprintf(stderr, "Failed to print ASN1 time into BIO.\n");
        rc = -1;
        goto cleanup;
    }
    BIO_puts(bio, "\0");
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *time_str = malloc((bptr->length + 1) * sizeof(char));
    if (!*time_str) {
        fprintf(stderr, "Failed to allocate memory for time string.\n");
        rc = -1;
        goto cleanup;
    }

    memcpy(*time_str, bptr->data, bptr->length);
    (*time_str)[bptr->length] = '\0';

cleanup:
    BIO_free(bio);

    return rc;
}

CU_STATUS cu_cert_get_not_before(const X509 *cert, char **not_before) {
    const ASN1_TIME *nb = X509_get0_notBefore(cert);

    if (asn1_time_to_buf(nb, not_before) != 0) {
        return CU_MEM_ERR;
    }
    return CU_OK;
}

CU_STATUS cu_cert_get_not_after(const X509 *cert, char **not_after) {
    const ASN1_TIME *na = X509_get0_notAfter(cert);

    if (asn1_time_to_buf(na, not_after) != 0) {
        return CU_MEM_ERR;
    }
    return CU_OK;
}

CU_STATUS cu_crl_get_last_update(const X509_CRL *crl, char **last_update) {
    const ASN1_TIME *lu = X509_CRL_get0_lastUpdate(crl);

    if (asn1_time_to_buf(lu, last_update) != 0) {
        return CU_MEM_ERR;
    }
    return CU_OK;
}

CU_STATUS cu_crl_get_next_update(const X509_CRL *crl, char **next_update) {
    const ASN1_TIME *nu = X509_CRL_get0_nextUpdate(crl);

    if (asn1_time_to_buf(nu, next_update) != 0) {
        return CU_MEM_ERR;
    }
    return CU_OK;
}

CU_STATUS cu_cert_get_extension(const X509 *cert, int nid, char **ext_data) {
    CU_STATUS rc = CU_OK;
    BUF_MEM *bptr = NULL;
    int idx = -1;

    idx = X509_get_ext_by_NID(cert, nid, -1);
    X509_EXTENSION *ext = X509_get_ext(cert, idx);

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ext, 0, 0)) {
        fprintf(stderr, "Failed to print extension data into BIO.\n");
        rc = CU_OSSL_ERR;
        goto cleanup;
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *ext_data = malloc((bptr->length + 1) * sizeof(char));
    if (!*ext_data) {
        fprintf(stderr, "Failed to allocate memory for extension data.\n");
        rc = CU_MEM_ERR;
        goto cleanup;
    }

    memcpy(*ext_data, bptr->data, bptr->length);
    (*ext_data)[bptr->length] = '\0';

cleanup:
    BIO_free(bio);

    return rc;
}

CU_STATUS cu_cert_get_fingerprint(const X509 *cert, const EVP_MD *digest_alg,
                                  char **fingerprint) {
    CU_STATUS rc = CU_OK;
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (digest_alg == NULL) {
        digest_alg = EVP_sha1();
    }

    if (!X509_digest(cert, digest_alg, md, &n)) {
        fprintf(stderr, "Failed to calculate fingerprint.\n");
        rc = CU_OSSL_ERR;
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    BIO_printf(bio, "%s Fingerprint=", OBJ_nid2sn(EVP_MD_type(digest_alg)));
    for (int j = 0; j < (int)n; j++) {
        BIO_printf(bio, "%02X%c", md[j], (j + 1 == (int)n) ? '\0' : ':');
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *fingerprint = malloc(
        bptr->length * sizeof(char)); // data of bptr is already NULL-terminated
    if (!*fingerprint) {
        fprintf(stderr, "Failed to allocate memory for extension data.\n");
        rc = CU_MEM_ERR;
        goto cleanup;
    }

    memcpy(*fingerprint, bptr->data, bptr->length);

cleanup:
    BIO_free(bio);

    return rc;
}
