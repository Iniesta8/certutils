#include "certutils.h"
#include "mock/openssl_mock.h"

#include "CppUTest/CommandLineTestRunner.h"

TEST_GROUP(CertutilsInfoCorrectInformationTest){};

TEST(CertutilsInfoCorrectInformationTest, CertSubjectName) {
    char *subject = NULL;
    X509 *cert = NULL;
    cu_cert_get_subject_name(cert, &subject);

    CHECK_TEXT(subject != NULL, "NULL returned by cu_cert_get_subject_name");
    STRCMP_EQUAL_TEXT(subject,
                      "\\CN=" MOCK_CN "\\C=" MOCK_C "\\O=" MOCK_O
                      "\\OU=" MOCK_OU "\\ST=" MOCK_ST "\\L=" MOCK_L,
                      "Wrong subject");
}

int main(int ac, char **av) {
    return CommandLineTestRunner::RunAllTests(ac, av);
}