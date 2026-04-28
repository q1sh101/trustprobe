#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "usbguard_rules.h"

size_t bythos_check_usbguard(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *rules_path = "/etc/usbguard/rules.conf";

    if (bythos_command_exists("usbguard")) {
        EMIT("usbguard installed", CHECK_OK, "binary found in PATH");
    } else {
        EMIT("usbguard installed", CHECK_FAIL, "binary not found");
    }

    switch (bythos_probe_systemd_service("usbguard.service")) {
    case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
        EMIT("usbguard active", CHECK_WARN, "systemctl not available");
        break;
    case BYTHOS_SERVICE_STATE_ACTIVE:
        EMIT("usbguard active", CHECK_OK, "running");
        break;
    case BYTHOS_SERVICE_STATE_INACTIVE:
        EMIT("usbguard active", CHECK_FAIL, "installed but inactive");
        break;
    case BYTHOS_SERVICE_STATE_MISSING:
        EMIT("usbguard active", CHECK_FAIL, "service unit not found");
        break;
    default:
        EMIT("usbguard active", CHECK_WARN, "unable to read unit state");
        break;
    }

    {
        struct stat rules_stat;
        if (stat(rules_path, &rules_stat) != 0) {
            EMIT("usbguard rules", CHECK_FAIL, "rules.conf not found");
        } else if (rules_stat.st_size > 0) {
            EMIT("usbguard rules", CHECK_OK, "conf present and non-empty");
        } else {
            EMIT("usbguard rules", CHECK_FAIL, "rules.conf exists but is empty");
        }
    }

    {
        FILE *rules_file = fopen(rules_path, "r");
        if (rules_file == NULL && errno == ENOENT) {
            EMIT("usbguard rule inventory", CHECK_SKIP, "rules.conf not found");
        } else if (rules_file == NULL) {
            /* Non-root runs should show visibility limits honestly instead of inventing a policy failure. */
            EMIT_ROOT("usbguard rule inventory", CHECK_SKIP, "rules.conf not readable");
        } else {
            fclose(rules_file);
            bythos_usbguard_rules_report_t report;
            if (!bythos_usbguard_rules_analyze(rules_path, &report)) {
                EMIT("usbguard rule inventory", CHECK_WARN, "unable to parse rules.conf");
            } else {
                char detail[128];
                snprintf(detail, sizeof(detail), "%zu rules / %zu allow entries", report.rule_count, report.allow_count);
                EMIT("usbguard rule inventory", CHECK_OK, detail);

                /* Wildcard allow rules defeat the point of a narrow hardware allowlist. */
                if (report.wildcard_allow_count > 0) {
                    snprintf(detail, sizeof(detail), "%zu wildcard allow rules found", report.wildcard_allow_count);
                    EMIT("usbguard wildcard rules", CHECK_FAIL, detail);
                } else {
                    EMIT("usbguard wildcard rules", CHECK_OK, "none detected");
                }

                /* External devices are expected to stay bound to explicit ports, not broad allow rules. */
                if (report.external_allow_count == 0) {
                    EMIT("usbguard external binding", CHECK_WARN, "no external allow rules detected");
                } else if (report.external_without_via_port_count > 0) {
                    snprintf(
                        detail,
                        sizeof(detail),
                        "%zu external allow rules are not port-bound",
                        report.external_without_via_port_count
                    );
                    EMIT("usbguard external binding", CHECK_FAIL, detail);
                } else {
                    snprintf(
                        detail,
                        sizeof(detail),
                        "%zu external allow rules are port-bound",
                        report.external_allow_count
                    );
                    EMIT("usbguard external binding", CHECK_OK, detail);
                }

                if (report.allow_without_hash_count > 0 || report.allow_without_connect_type_count > 0) {
                    snprintf(
                        detail,
                        sizeof(detail),
                        "%zu without hash, %zu without connect-type",
                        report.allow_without_hash_count,
                        report.allow_without_connect_type_count
                    );
                    EMIT("usbguard rule metadata", CHECK_WARN, detail);
                } else {
                    EMIT("usbguard rule metadata", CHECK_OK, "allow rules have hash and connect-type");
                }
            }
        }
    }

    return used;
}
