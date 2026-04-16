#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "silicon_parsers.h"

int main(void) {
    trustprobe_iommu_cmdline_t parsed = {0};
    char revision[64] = {0};

    trustprobe_parse_iommu_cmdline("quiet splash iommu.passthrough=0 iommu.strict=1", &parsed);
    assert_true("iommu_passthrough_off", parsed.passthrough_off);
    assert_true("iommu_strict_on", parsed.strict_on);
    assert_false("iommu_passthrough_on_absent", parsed.passthrough_on);
    assert_false("iommu_disabled_absent", parsed.iommu_disabled);

    trustprobe_parse_iommu_cmdline("root=UUID=abc iommu=pt", &parsed);
    assert_true("iommu_pt", parsed.passthrough_on);

    trustprobe_parse_iommu_cmdline("root=UUID=abc intel_iommu=off", &parsed);
    assert_true("iommu_disabled", parsed.iommu_disabled);

    trustprobe_parse_iommu_cmdline("root=UUID=abc amd_iommu=on", &parsed);
    assert_true("vendor_iommu_on", parsed.vendor_iommu_on);

    trustprobe_parse_iommu_cmdline("root=UUID=abc iommu=offline some_other_iommu=off", &parsed);
    assert_false("iommu_offline_false_positive", parsed.iommu_disabled);

    trustprobe_parse_iommu_cmdline("quiet splash iommu.strict=0", &parsed);
    assert_true("iommu_strict_off", parsed.strict_off);
    assert_false("iommu_strict_off_not_disabled", parsed.iommu_disabled);
    assert_false("iommu_strict_off_not_passthrough", parsed.passthrough_on);

    assert_true(
        "microcode_revision",
        trustprobe_extract_microcode_revision(
            "processor\t: 0\nvendor_id\t: GenuineIntel\nmicrocode\t: 0x2f\ncpu MHz\t\t: 1000.000\n",
            revision,
            sizeof(revision)
        )
    );
    assert_true("microcode_revision_value", strcmp(revision, "0x2f") == 0);

    assert_false(
        "microcode_missing",
        trustprobe_extract_microcode_revision(
            "processor\t: 0\nvendor_id\t: GenuineIntel\n",
            revision,
            sizeof(revision)
        )
    );

    /* skip writes when output storage is absent */
    trustprobe_parse_iommu_cmdline("quiet splash", NULL);

    printf("silicon parsers ok\n");
    return 0;
}
