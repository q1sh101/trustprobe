#include <stdio.h>
#include <stdlib.h>

#include "assert_helpers.h"
#include "usbguard_rules.h"

typedef struct {
    const char *path;
    size_t rule_count;
    size_t allow_count;
    size_t wildcard_allow_count;
    size_t allow_without_hash_count;
    size_t allow_without_connect_type_count;
    size_t external_allow_count;
    size_t external_without_via_port_count;
    size_t via_port_count;
} case_t;

static void assert_eq_size(const char *field, size_t want, size_t got, const char *path) {
    if (want == got) {
        return;
    }

    fprintf(
        stderr,
        "rules parser failure: %s expected %zu, got %zu for %s\n",
        field,
        want,
        got,
        path
    );
    exit(1);
}

int main(void) {
    trustprobe_usbguard_rules_report_t report = {0};
    const case_t cases[] = {
        {
            .path = "tests/fixtures/rules/good.conf",
            .rule_count = 2,
            .allow_count = 2,
            .wildcard_allow_count = 0,
            .allow_without_hash_count = 0,
            .allow_without_connect_type_count = 0,
            .external_allow_count = 1,
            .external_without_via_port_count = 0,
            .via_port_count = 2,
        },
        {
            .path = "tests/fixtures/rules/wildcard.conf",
            .rule_count = 1,
            .allow_count = 1,
            .wildcard_allow_count = 1,
            .allow_without_hash_count = 1,
            .allow_without_connect_type_count = 1,
            .external_allow_count = 1,
            .external_without_via_port_count = 1,
            .via_port_count = 0,
        },
        {
            .path = "tests/fixtures/rules/hotplug_without_via.conf",
            .rule_count = 1,
            .allow_count = 1,
            .wildcard_allow_count = 0,
            .allow_without_hash_count = 0,
            .allow_without_connect_type_count = 0,
            .external_allow_count = 1,
            .external_without_via_port_count = 1,
            .via_port_count = 0,
        },
    };

    assert_false("rules_null_path", trustprobe_usbguard_rules_analyze(NULL, &report));
    assert_false("rules_null_report", trustprobe_usbguard_rules_analyze("tests/fixtures/rules/good.conf", NULL));

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!trustprobe_usbguard_rules_analyze(cases[i].path, &report)) {
            fprintf(stderr, "rules parser failure: could not read %s\n", cases[i].path);
            return 1;
        }

        assert_eq_size("rule_count", cases[i].rule_count, report.rule_count, cases[i].path);
        assert_eq_size("allow_count", cases[i].allow_count, report.allow_count, cases[i].path);
        assert_eq_size("wildcard_allow_count", cases[i].wildcard_allow_count, report.wildcard_allow_count, cases[i].path);
        assert_eq_size("allow_without_hash_count", cases[i].allow_without_hash_count, report.allow_without_hash_count, cases[i].path);
        assert_eq_size(
            "allow_without_connect_type_count",
            cases[i].allow_without_connect_type_count,
            report.allow_without_connect_type_count,
            cases[i].path
        );
        assert_eq_size("external_allow_count", cases[i].external_allow_count, report.external_allow_count, cases[i].path);
        assert_eq_size(
            "external_without_via_port_count",
            cases[i].external_without_via_port_count,
            report.external_without_via_port_count,
            cases[i].path
        );
        assert_eq_size("via_port_count", cases[i].via_port_count, report.via_port_count, cases[i].path);
    }

    printf("rules parser ok\n");
    return 0;
}
