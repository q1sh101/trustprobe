#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "output.h"

enum {
    BYTHOS_EXIT_OK = 0,
    BYTHOS_EXIT_FAIL = 1,
    BYTHOS_EXIT_USAGE = 2,
};

#define BYTHOS_VERSION "0.1.0"

static void usage(const char *argv0) {
    printf(
        "usage: %s [all|physical|firmware] [-j|--json]\n"
        "\n"
        "  -j, --json     machine-readable JSON output (scripts, CI, pipes)\n"
        "  -h, --help     show this help and exit\n"
        "  -V, --version  print version and exit\n"
        "\n"
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
    bythos_render_mode_t render_mode = BYTHOS_RENDER_PLAIN;
    posture_summary_t overall = {0};
    const char *mode = "all";
    int exit_code = BYTHOS_EXIT_OK;
    check_subgroup_t physical_subgroups[BYTHOS_MAX_GROUP_SUBGROUPS];
    check_subgroup_t firmware_subgroups[BYTHOS_MAX_GROUP_SUBGROUPS];
    posture_summary_t physical_summary = {0};
    posture_summary_t firmware_summary = {0};
    size_t physical_subgroup_count = 0;
    size_t firmware_subgroup_count = 0;

    const char *selected_mode = NULL;

    static const struct option long_options[] = {
        {"help",    no_argument, NULL, 'h'},
        {"json",    no_argument, NULL, 'j'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hjV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'j':
            render_mode = BYTHOS_RENDER_JSON;
            break;
        case 'V':
            printf("bythos %s\n", BYTHOS_VERSION);
            return 0;
        default:
            usage(argv[0]);
            return BYTHOS_EXIT_USAGE;
        }
    }

    if (optind < argc) {
        if (optind + 1 != argc) {
            usage(argv[0]);
            return BYTHOS_EXIT_USAGE;
        }
        if (strcmp(argv[optind], "all") == 0 ||
            strcmp(argv[optind], "physical") == 0 ||
            strcmp(argv[optind], "firmware") == 0) {
            selected_mode = argv[optind];
        } else {
            usage(argv[0]);
            return BYTHOS_EXIT_USAGE;
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
        firmware_subgroup_count = bythos_check_firmware(
            firmware_subgroups, BYTHOS_MAX_GROUP_SUBGROUPS);
        for (size_t i = 0; i < firmware_subgroup_count; i++) {
            bythos_summary_merge(&firmware_summary, &firmware_subgroups[i].summary);
            bythos_summary_merge(&overall, &firmware_subgroups[i].summary);
        }
    }
    if (run_physical) {
        physical_subgroup_count = bythos_check_physical(
            physical_subgroups, BYTHOS_MAX_GROUP_SUBGROUPS);
        for (size_t i = 0; i < physical_subgroup_count; i++) {
            bythos_summary_merge(&physical_summary, &physical_subgroups[i].summary);
            bythos_summary_merge(&overall, &physical_subgroups[i].summary);
        }
    }

    exit_code = overall.fail_count > 0 ? BYTHOS_EXIT_FAIL : BYTHOS_EXIT_OK;

    bythos_group_view_t groups[2];
    size_t group_count = 0;

    if (run_firmware) {
        groups[group_count++] = (bythos_group_view_t){
            .name = "firmware",
            .subgroups = firmware_subgroups,
            .subgroup_count = firmware_subgroup_count,
            .summary = &firmware_summary,
        };
    }
    if (run_physical) {
        groups[group_count++] = (bythos_group_view_t){
            .name = "physical",
            .subgroups = physical_subgroups,
            .subgroup_count = physical_subgroup_count,
            .summary = &physical_summary,
        };
    }

    bythos_render(render_mode, mode,
                  banner_text(run_physical, run_firmware),
                  groups, group_count, &overall, exit_code);
    return exit_code;
}
