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
    size_t used = 0;

    if (used < max_results) {
        char val[16] = {0};
        if (!trustprobe_read_file_text(
                "/sys/module/usbcore/parameters/authorized_default",
                val, sizeof(val))) {
            results[used++] = make_result("usbcore authorized default", CHECK_SKIP,
                "parameter not readable");
        } else {
            char *trimmed = trustprobe_trim(val);
            if (strcmp(trimmed, "0") == 0) {
                results[used++] = make_result("usbcore authorized default", CHECK_OK,
                    "USB devices denied by default until authorized");
            } else if (strcmp(trimmed, "2") == 0) {
                results[used++] = make_result("usbcore authorized default", CHECK_OK,
                    "USB authorization: internal devices only");
            } else {
                results[used++] = make_result("usbcore authorized default", CHECK_WARN,
                    "usbcore.authorized_default=1; devices authorized before usbguard starts");
            }
        }
    }

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
        if (used < max_results) {
            results[used++] = make_result("usbguard daemon policy", CHECK_FAIL, "usbguard-daemon.conf not found");
        }
        return used;
    }

    if (probe == NULL) {
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
