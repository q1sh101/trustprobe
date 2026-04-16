#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"

typedef struct {
    const char *key;
    const char *expected;
    const char *name;
} policy_expectation_t;

size_t trustprobe_check_usbguard_policy(check_result_t *results, size_t max_results) {
    static const policy_expectation_t expectations[] = {
        {"ImplicitPolicyTarget", "block", "usbguard implicit policy"},
        {"PresentDevicePolicy", "apply-policy", "usbguard present device policy"},
        {"InsertedDevicePolicy", "apply-policy", "usbguard inserted device policy"},
        {"AuthorizedDefault", "none", "usbguard authorized default"},
        {"IPCAllowedUsers", "root", "usbguard IPC users"},
        {"IPCAllowedGroups", "", "usbguard IPC groups"},
        {"DeviceRulesWithPort", "true", "usbguard port-bound rules"},
        {"HidePII", "true", "usbguard PII hiding"},
    };

    const char *path = "/etc/usbguard/usbguard-daemon.conf";
    FILE *probe = fopen(path, "r");
    if (probe == NULL && errno == ENOENT) {
        if (max_results > 0) {
            results[0] = make_result("usbguard daemon policy", CHECK_FAIL, "usbguard-daemon.conf not found");
            return 1;
        }
        return 0;
    }

    if (probe == NULL) {
        size_t used = 0;
        for (size_t i = 0; i < sizeof(expectations) / sizeof(expectations[0]) && used < max_results; i++) {
            results[used++] = make_root_result(
                expectations[i].name,
                CHECK_SKIP,
                "config not readable"
            );
        }
        return used;
    }

    fclose(probe);

    size_t used = 0;
    for (size_t i = 0; i < sizeof(expectations) / sizeof(expectations[0]) && used < max_results; i++) {
        char value[128] = {0};
        if (!trustprobe_read_key_value(path, expectations[i].key, value, sizeof(value))) {
            results[used++] = make_result(expectations[i].name, CHECK_FAIL, "key not found");
            continue;
        }

        if (strcmp(value, expectations[i].expected) == 0) {
            results[used++] = make_result(expectations[i].name, CHECK_OK, value[0] ? value : "<empty>");
        } else {
            char detail[128];
            snprintf(
                detail,
                sizeof(detail),
                "expected %.48s, got %.48s",
                expectations[i].expected[0] ? expectations[i].expected : "<empty>",
                value[0] ? value : "<empty>"
            );
            results[used++] = make_result(expectations[i].name, CHECK_FAIL, detail);
        }
    }

    return used;
}
