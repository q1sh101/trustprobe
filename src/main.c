#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "output.h"

enum {
    TRUSTPROBE_EXIT_OK = 0,
    TRUSTPROBE_EXIT_FAIL = 1,
    TRUSTPROBE_EXIT_USAGE = 2,
};

static void usage(const char *argv0) {
    printf(
        "usage: %s [--json] [all|physical|firmware]\n"
        "\n"
        "  --json    machine-readable JSON output (scripts, CI, pipes)\n"
        "  all       run all trust boundary checks (default)\n"
        "  physical  run USB / desktop physical-trust checks\n"
        "  firmware  run Secure Boot / fwupd / signing checks\n",
        argv0
    );
}

static const char *banner_text(bool run_physical, bool run_firmware) {
    if (run_physical && run_firmware) return "firmware trust + physical posture";
    if (run_firmware) return "firmware trust posture";
    if (run_physical) return "physical trust posture";
    return "trust posture";
}

int main(int argc, char **argv) {
    bool run_physical = true;
    bool run_firmware = true;
    trustprobe_render_mode_t render_mode = TRUSTPROBE_RENDER_PLAIN;
    posture_summary_t overall = {0};
    const char *mode = "all";
    int exit_code = TRUSTPROBE_EXIT_OK;
    check_subgroup_t physical_subgroups[TRUSTPROBE_MAX_GROUP_SUBGROUPS];
    check_subgroup_t firmware_subgroups[TRUSTPROBE_MAX_GROUP_SUBGROUPS];
    posture_summary_t physical_summary = {0};
    posture_summary_t firmware_summary = {0};
    size_t physical_subgroup_count = 0;
    size_t firmware_subgroup_count = 0;

    const char *selected_mode = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--json") == 0) {
            if (render_mode != TRUSTPROBE_RENDER_PLAIN) {
                usage(argv[0]);
                return TRUSTPROBE_EXIT_USAGE;
            }
            render_mode = TRUSTPROBE_RENDER_JSON;
        } else if (strcmp(argv[i], "all") == 0 ||
                   strcmp(argv[i], "physical") == 0 ||
                   strcmp(argv[i], "firmware") == 0) {
            if (selected_mode != NULL) {
                usage(argv[0]);
                return TRUSTPROBE_EXIT_USAGE;
            }
            selected_mode = argv[i];
        } else {
            usage(argv[0]);
            return TRUSTPROBE_EXIT_USAGE;
        }
    }

    if (selected_mode != NULL) {
        mode = selected_mode;
    }

    if (strcmp(mode, "all") == 0) {
        run_physical = true;
        run_firmware = true;
    } else if (strcmp(mode, "physical") == 0) {
        run_physical = true;
        run_firmware = false;
    } else {
        run_physical = false;
        run_firmware = true;
    }

    if (run_firmware) {
        firmware_subgroup_count = trustprobe_check_firmware(
            firmware_subgroups, TRUSTPROBE_MAX_GROUP_SUBGROUPS);
        for (size_t i = 0; i < firmware_subgroup_count; i++) {
            trustprobe_summary_merge(&firmware_summary, &firmware_subgroups[i].summary);
            trustprobe_summary_merge(&overall, &firmware_subgroups[i].summary);
        }
    }
    if (run_physical) {
        physical_subgroup_count = trustprobe_check_physical(
            physical_subgroups, TRUSTPROBE_MAX_GROUP_SUBGROUPS);
        for (size_t i = 0; i < physical_subgroup_count; i++) {
            trustprobe_summary_merge(&physical_summary, &physical_subgroups[i].summary);
            trustprobe_summary_merge(&overall, &physical_subgroups[i].summary);
        }
    }

    exit_code = overall.fail_count > 0 ? TRUSTPROBE_EXIT_FAIL : TRUSTPROBE_EXIT_OK;

    trustprobe_group_view_t groups[2];
    size_t group_count = 0;

    if (run_firmware) {
        groups[group_count++] = (trustprobe_group_view_t){
            .name = "firmware",
            .subgroups = firmware_subgroups,
            .subgroup_count = firmware_subgroup_count,
            .summary = &firmware_summary,
        };
    }
    if (run_physical) {
        groups[group_count++] = (trustprobe_group_view_t){
            .name = "physical",
            .subgroups = physical_subgroups,
            .subgroup_count = physical_subgroup_count,
            .summary = &physical_summary,
        };
    }

    trustprobe_render(render_mode, mode,
                  banner_text(run_physical, run_firmware),
                  groups, group_count, &overall, exit_code);
    return exit_code;
}
