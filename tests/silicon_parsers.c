#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "silicon_parsers.h"

int main(void) {
    bythos_iommu_cmdline_t parsed = {0};
    char revision[64] = {0};

    bythos_parse_iommu_cmdline("quiet splash iommu.passthrough=0 iommu.strict=1", &parsed);
    assert_true("iommu_passthrough_off", parsed.passthrough_off);
    assert_true("iommu_strict_on", parsed.strict_on);
    assert_false("iommu_passthrough_on_absent", parsed.passthrough_on);
    assert_false("iommu_disabled_absent", parsed.iommu_disabled);

    bythos_parse_iommu_cmdline("root=UUID=abc iommu=pt", &parsed);
    assert_true("iommu_pt", parsed.passthrough_on);

    bythos_parse_iommu_cmdline("root=UUID=abc intel_iommu=off", &parsed);
    assert_true("iommu_disabled", parsed.iommu_disabled);

    bythos_parse_iommu_cmdline("root=UUID=abc amd_iommu=on", &parsed);
    assert_true("vendor_iommu_on", parsed.vendor_iommu_on);

    bythos_parse_iommu_cmdline("root=UUID=abc iommu=offline some_other_iommu=off", &parsed);
    assert_false("iommu_offline_false_positive", parsed.iommu_disabled);

    bythos_parse_iommu_cmdline("quiet splash iommu.strict=0", &parsed);
    assert_true("iommu_strict_off", parsed.strict_off);
    assert_false("iommu_strict_off_not_disabled", parsed.iommu_disabled);
    assert_false("iommu_strict_off_not_passthrough", parsed.passthrough_on);

    assert_true(
        "microcode_revision",
        bythos_extract_microcode_revision(
            "processor\t: 0\nvendor_id\t: GenuineIntel\nmicrocode\t: 0x2f\ncpu MHz\t\t: 1000.000\n",
            revision,
            sizeof(revision)
        )
    );
    assert_true("microcode_revision_value", strcmp(revision, "0x2f") == 0);

    assert_false(
        "microcode_missing",
        bythos_extract_microcode_revision(
            "processor\t: 0\nvendor_id\t: GenuineIntel\n",
            revision,
            sizeof(revision)
        )
    );

    /* skip writes when output storage is absent */
    bythos_parse_iommu_cmdline("quiet splash", NULL);

    assert_eq_int("pcr_zero_all_zeros",
        bythos_pcr_zero_check(
            "sha256:\n  0 : 0x0000000000000000000000000000000000000000000000000000000000000000\n",
            0), 1);
    assert_eq_int("pcr_zero_nonzero",
        bythos_pcr_zero_check(
            "sha256:\n  0 : 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n",
            0), 0);
    assert_eq_int("pcr7_all_zeros",
        bythos_pcr_zero_check(
            "sha256:\n  7 : 0x0000000000000000000000000000000000000000000000000000000000000000\n",
            7), 1);
    assert_eq_int("pcr_not_found",
        bythos_pcr_zero_check("sha256:\n  7 : 0x1234...\n", 0), -1);
    assert_eq_int("pcr_null",
        bythos_pcr_zero_check(NULL, 0), -1);
    assert_eq_int("pcr_compact_colon",
        bythos_pcr_zero_check("0: 0x0000000000000000000000000000000000000000000000000000000000000000\n", 0), 1);

    printf("silicon parsers ok\n");
    return 0;
}
