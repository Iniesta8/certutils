#include <stdio.h>
#include <stdlib.h>

#include "certutils.h"
#include "helper.h"

int main() {
    // cu_cert_conv_pem2der("test.pem", "test.der");
    // cu_conv_der2pem("test1.der", "test1.pem");
    // cu_conv_pem2der("test1.pem", "test2.der");
    // cu_conv_der2pem("test2.der", "test2.pem");

    X509 *cert = NULL;
    X509_CRL *crl = NULL;

    CU_FILETYPE certt = cu_get_file_type("testfiles/selfsign-cert.pem");
    CU_FILETYPE crlt = cu_get_file_type("testfiles/selfsign.crl");
    CU_FILETYPE pubkeyt = cu_get_file_type("testfiles/pubkey.pem");
    CU_FILETYPE privkeyt = cu_get_file_type("testfiles/privkey.pem");

    printf("filetype of 'selfsign-cert.pem' is %d\n", certt);
    printf("filetype of 'test.crl' is %d\n", crlt);
    printf("filetype of 'pubkey.pem' is %d\n", pubkeyt);
    printf("filetype of 'privkey.pem' is %d\n", privkeyt);

    cu_read_cert("testfiles/selfsign-cert.pem", &cert);
    cu_read_crl("test.crl", &crl);

    char *subject = NULL;
    char *issuer = NULL;
    char *serial_number = NULL;
    char *not_before = NULL;
    char *not_after = NULL;
    char *ext_data = NULL;
    char *fp_default = NULL;
    char *last_update = NULL;
    char *next_update = NULL;

    cu_cert_get_subject_name(cert, &subject);
    printf("%s\n", subject);
    cu_cert_get_issuer_name(cert, &issuer);
    printf("%s\n", issuer);
    cu_cert_get_serial_number(cert, &serial_number);
    printf("%s\n", serial_number);
    cu_cert_get_not_before(cert, &not_before);
    cu_cert_get_not_after(cert, &not_after);
    cu_cert_get_fingerprint(cert, NULL, &fp_default);
    cu_crl_get_last_update(crl, &last_update);
    cu_crl_get_next_update(crl, &next_update);

    cu_cert_get_extension(cert, CU_NID_key_usage, &ext_data);

    printf("serial number: %s\n", serial_number);
    printf("not before: %s\n", not_before);
    printf("not after: %s\n", not_after);
    printf("ext data 'key usage': %s\n", ext_data);
    printf("fp: %s\n", fp_default);
    printf("last update: %s\n", last_update);
    printf("next update: %s\n", next_update);

    free_cert(&cert);
    free_crl(&crl);
    free(subject);
    free(issuer);
    free(serial_number);
    free(not_before);
    free(not_after);
    free(ext_data);
    free(fp_default);
    free(last_update);
    free(next_update);

    return 0;
}
