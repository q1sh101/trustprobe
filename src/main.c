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
        "usage: %s [all|physical|firmware|kernel]\n"
        "\n"
        "  all       run all trust boundary checks (default)\n"
        "  physical  run USB / desktop physical-trust checks\n"
        "  firmware  run Secure Boot / fwupd / signing checks\n"
        "  kernel    run kernel lockdown / sysctl posture checks\n",
        argv0
    );
}

static const char *banner_text(bool run_physical, bool run_firmware, bool run_kernel) {
    if (run_physical && run_firmware && run_kernel) {
        return "physical trust + firmware + kernel posture";
    }
    if (run_physical && run_firmware) {
        return "physical trust + firmware posture";
    }
    if (run_physical && run_kernel) {
        return "physical trust + kernel posture";
    }
    if (run_firmware && run_kernel) {
        return "firmware + kernel posture";
    }
    if (run_physical) {
        return "physical trust posture";
    }
    if (run_firmware) {
        return "firmware trust posture";
    }
    if (run_kernel) {
        return "kernel posture";
    }
    return "trust posture";
}

int main(int argc, char **argv) {
    bool run_physical = true;
    bool run_firmware = true;
    bool run_kernel = true;
    posture_summary_t overall = {0};
    const char *mode = "all";
    int exit_code = TRUSTPROBE_EXIT_OK;
    check_result_t physical_results[TRUSTPROBE_MAX_GROUP_RESULTS];
    check_result_t firmware_results[TRUSTPROBE_MAX_GROUP_RESULTS];
    check_result_t kernel_results[TRUSTPROBE_MAX_GROUP_RESULTS];
    posture_summary_t physical_summary = {0};
    posture_summary_t firmware_summary = {0};
    posture_summary_t kernel_summary = {0};
    size_t physical_count = 0;
    size_t firmware_count = 0;
    size_t kernel_count = 0;

    const char *selected_mode = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "all") == 0 ||
                   strcmp(argv[i], "physical") == 0 ||
                   strcmp(argv[i], "firmware") == 0 ||
                   strcmp(argv[i], "kernel") == 0) {
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
        run_kernel = true;
    } else if (strcmp(mode, "physical") == 0) {
        run_physical = true;
        run_firmware = false;
        run_kernel = false;
    } else if (strcmp(mode, "firmware") == 0) {
        run_physical = false;
        run_firmware = true;
        run_kernel = false;
    } else {
        run_physical = false;
        run_firmware = false;
        run_kernel = true;
    }

    if (run_physical) {
        physical_count = trustprobe_check_physical(physical_results, TRUSTPROBE_MAX_GROUP_RESULTS);
        for (size_t i = 0; i < physical_count; i++) {
            trustprobe_summary_add(&physical_summary, &physical_results[i]);
            trustprobe_summary_add(&overall, &physical_results[i]);
        }
    }
    if (run_firmware) {
        firmware_count = trustprobe_check_firmware(firmware_results, TRUSTPROBE_MAX_GROUP_RESULTS);
        for (size_t i = 0; i < firmware_count; i++) {
            trustprobe_summary_add(&firmware_summary, &firmware_results[i]);
            trustprobe_summary_add(&overall, &firmware_results[i]);
        }
    }
    if (run_kernel) {
        kernel_count = trustprobe_check_kernel(kernel_results, TRUSTPROBE_MAX_GROUP_RESULTS);
        for (size_t i = 0; i < kernel_count; i++) {
            trustprobe_summary_add(&kernel_summary, &kernel_results[i]);
            trustprobe_summary_add(&overall, &kernel_results[i]);
        }
    }

    exit_code = overall.fail_count > 0 ? TRUSTPROBE_EXIT_FAIL : TRUSTPROBE_EXIT_OK;

    trustprobe_log("%s", banner_text(run_physical, run_firmware, run_kernel));
    putchar('\n');

    if (run_physical) {
        trustprobe_log("%s", "physical");
        for (size_t i = 0; i < physical_count; i++) {
            trustprobe_print_result(&physical_results[i]);
        }
        trustprobe_print_summary("physical", &physical_summary);
        putchar('\n');
    }
    if (run_firmware) {
        trustprobe_log("%s", "firmware");
        for (size_t i = 0; i < firmware_count; i++) {
            trustprobe_print_result(&firmware_results[i]);
        }
        trustprobe_print_summary("firmware", &firmware_summary);
        putchar('\n');
    }
    if (run_kernel) {
        trustprobe_log("%s", "kernel");
        for (size_t i = 0; i < kernel_count; i++) {
            trustprobe_print_result(&kernel_results[i]);
        }
        trustprobe_print_summary("kernel", &kernel_summary);
        putchar('\n');
    }

    trustprobe_print_summary("overall", &overall);

    return exit_code;
}
