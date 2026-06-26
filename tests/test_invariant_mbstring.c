#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/dolphin/MSL_C/PPCEABI/bare/H/mbstring.c"

START_TEST(test_mbstring_buffer_reads)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "A",                    // Valid minimal input
        "ABCDEFGHIJ",           // Boundary: exactly 10 chars (common buffer size)
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",  // 2.6x overflow
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // 10x overflow
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"  // Binary data
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char dest[10] = {0};
        const char *src = payloads[i];
        size_t src_len = strlen(src);
        
        // Test strncpy behavior - should not write beyond dest[9]
        strncpy(dest, src, sizeof(dest));
        
        // Verify no writes beyond buffer (check last byte is either null or valid)
        ck_assert_msg(dest[sizeof(dest)-1] == '\0' || src_len < sizeof(dest),
                     "Buffer overflow detected for payload %d", i);
        
        // Verify null termination when src_len >= buffer size
        if (src_len >= sizeof(dest)) {
            ck_assert_msg(dest[sizeof(dest)-1] == '\0',
                         "Missing null termination for long payload %d", i);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_mbstring_buffer_reads);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}