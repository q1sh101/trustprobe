#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "checks.h"
#include "runtime.h"
#include "usbguard_rules.h"

size_t trustprobe_check_usbguard(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *rules_path = "/etc/usbguard/rules.conf";

    if (used < max_results) {
        if (trustprobe_command_exists("usbguard")) {
            results[used++] = make_result("usbguard installed", CHECK_OK, "binary found in PATH");
        } else {
            results[used++] = make_result("usbguard installed", CHECK_FAIL, "binary not found");
        }
    }

    if (used < max_results) {
        switch (trustprobe_probe_systemd_service("usbguard.service")) {
        case TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
            results[used++] = make_result("usbguard active", CHECK_WARN, "systemctl not available");
            break;
        case TRUSTPROBE_SERVICE_STATE_ACTIVE:
            results[used++] = make_result("usbguard active", CHECK_OK, "service is running");
            break;
        case TRUSTPROBE_SERVICE_STATE_INACTIVE:
            results[used++] = make_result("usbguard active", CHECK_FAIL, "installed but inactive");
            break;
        case TRUSTPROBE_SERVICE_STATE_MISSING:
            results[used++] = make_result("usbguard active", CHECK_FAIL, "service unit not found");
            break;
        default:
            results[used++] = make_result("usbguard active", CHECK_WARN, "unable to read unit state");
            break;
        }
    }

    if (used < max_results) {
        struct stat rules_stat;
        if (stat(rules_path, &rules_stat) != 0) {
            results[used++] = make_result("usbguard rules", CHECK_FAIL, "rules.conf not found");
        } else if (rules_stat.st_size > 0) {
            results[used++] = make_result("usbguard rules", CHECK_OK, "rules.conf present and non-empty");
        } else {
            results[used++] = make_result("usbguard rules", CHECK_FAIL, "rules.conf exists but is empty");
        }
    }

    if (used < max_results) {
        FILE *rules_file = fopen(rules_path, "r");
        if (rules_file == NULL && errno == ENOENT) {
            results[used++] = make_result("usbguard rule inventory", CHECK_SKIP, "rules.conf not found");
        } else if (rules_file == NULL) {
            /* Non-root runs should show visibility limits honestly instead of inventing a policy failure. */
            results[used++] = make_root_result("usbguard rule inventory", CHECK_SKIP, "rules.conf not readable");
        } else {
            fclose(rules_file);
            trustprobe_usbguard_rules_report_t report;
            if (!trustprobe_usbguard_rules_analyze(rules_path, &report)) {
                results[used++] = make_result("usbguard rule inventory", CHECK_WARN, "unable to parse rules.conf");
            } else {
                char detail[128];
                snprintf(detail, sizeof(detail), "%zu rules / %zu allow entries", report.rule_count, report.allow_count);
                results[used++] = make_result("usbguard rule inventory", CHECK_OK, detail);

                if (used < max_results) {
                    /* Wildcard allow rules defeat the point of a narrow hardware allowlist. */
                    if (report.wildcard_allow_count > 0) {
                        snprintf(detail, sizeof(detail), "%zu wildcard allow rules found", report.wildcard_allow_count);
                        results[used++] = make_result("usbguard wildcard rules", CHECK_FAIL, detail);
                    } else {
                        results[used++] = make_result("usbguard wildcard rules", CHECK_OK, "no wildcard allow rules detected");
                    }
                }

                if (used < max_results) {
                    /* External devices are expected to stay bound to explicit ports, not broad allow rules. */
                    if (report.external_allow_count == 0) {
                        results[used++] = make_result("usbguard external binding", CHECK_WARN, "no external allow rules detected");
                    } else if (report.external_without_via_port_count > 0) {
                        snprintf(
                            detail,
                            sizeof(detail),
                            "%zu external allow rules are not port-bound",
                            report.external_without_via_port_count
                        );
                        results[used++] = make_result("usbguard external binding", CHECK_FAIL, detail);
                    } else {
                        snprintf(
                            detail,
                            sizeof(detail),
                            "%zu external allow rules are port-bound",
                            report.external_allow_count
                        );
                        results[used++] = make_result("usbguard external binding", CHECK_OK, detail);
                    }
                }

                if (used < max_results) {
                    if (report.allow_without_hash_count > 0 || report.allow_without_connect_type_count > 0) {
                        snprintf(
                            detail,
                            sizeof(detail),
                            "%zu without hash / %zu without connect-type",
                            report.allow_without_hash_count,
                            report.allow_without_connect_type_count
                        );
                        results[used++] = make_result("usbguard rule metadata", CHECK_WARN, detail);
                    } else {
                        results[used++] = make_result("usbguard rule metadata", CHECK_OK, "allow rules have hash and connect-type");
                    }
                }
            }
        }
    }

    return used;
}
