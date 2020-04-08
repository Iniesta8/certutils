#include "certutils.h"
#include "helper.h"

CU_STATUS cu_cert_conv_pem2der(const char *pem_cert, const char *der_cert) {
    CU_STATUS rc = CU_OK;
    X509 *cert = NULL;

    rc = cu_read_cert(pem_cert, &cert);
    if (CU_OK != rc) {
        return rc;
    }

    FILE *fp = fopen(der_cert, "w+");
    if (!fp) {
        fprintf(stderr, "Failed to open output cert file for writing.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    int res = i2d_X509_fp(fp, cert);
    if (res < 0) {
        fprintf(stderr, "Failed to write data to output cert file.\n");
        rc = CU_OSSL_ERR;
        goto cleanup;
    }

cleanup:
    if (fp) {
        fclose(fp);
    }
    free_cert(&cert);

    return rc;
}

CU_STATUS cu_cert_conv_der2pem(const char *der_cert, const char *pem_cert) {
    CU_STATUS rc = CU_OK;
    X509 *cert = NULL;
    FILE *fp_in = NULL;
    FILE *fp_out = NULL;

    fp_in = fopen(der_cert, "rb");
    if (!fp_in) {
        fprintf(stderr, "Failed to open file for reading.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    fp_out = fopen(pem_cert, "w+");
    if (!fp_out) {
        fprintf(stderr, "Failed to open file for writing.\n");
        rc = CU_STREAM_ERR;
        goto cleanup;
    }

    cert = d2i_X509_fp(fp_in, NULL);
    if (cert) {
        PEM_write_X509(fp_out, cert);
    } else {
        fprintf(stderr, "Failed to parse input data to PEM.\n");
        rc = CU_OSSL_ERR;
        goto cleanup;
    }

cleanup:
    if (fp_in) {
        fclose(fp_in);
    }
    if (fp_out) {
        fclose(fp_out);
    }
    free_cert(&cert);

    return rc;
}
