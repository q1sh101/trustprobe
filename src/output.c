#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "output.h"

static bool use_color(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *no_color = getenv("NO_COLOR");
        const char *term = getenv("TERM");
        cached = (no_color == NULL || *no_color == '\0')
                 && isatty(fileno(stdout)) != 0
                 && term != NULL
                 && strcmp(term, "dumb") != 0
                 && strcmp(term, "linux") != 0;
    }
    return cached != 0;
}

static const char *c_reset(void) { return use_color() ? "\033[0m" : ""; }
static const char *c_brand(void) { return use_color() ? "\033[1;38;5;220m" : ""; }
static const char *c_blue(void) { return use_color() ? "\033[38;5;51m" : ""; }
static const char *c_accent(void) { return use_color() ? "\033[38;5;123m" : ""; }
static const char *c_green(void) { return use_color() ? "\033[38;5;82m" : ""; }
static const char *c_yellow(void) { return use_color() ? "\033[38;5;214m" : ""; }
static const char *c_red(void) { return use_color() ? "\033[38;5;196m" : ""; }
static const char *c_dim(void) { return use_color() ? "\033[38;5;248m" : ""; }

static const char *state_color(check_state_t state) {
    switch (state) {
    case CHECK_OK:
        return c_green();
    case CHECK_WARN:
        return c_yellow();
    case CHECK_FAIL:
        return c_red();
    case CHECK_SKIP:
        return c_dim();
    }
    return "";
}

static void vprint_prefixed(FILE *stream, const char *color, const char *label, const char *fmt, va_list args) {
    fprintf(stream, "  %s%s%s ", color, label, c_reset());
    vfprintf(stream, fmt, args);
    fputc('\n', stream);
}

static void trustprobe_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprint_prefixed(stdout, c_brand(), "[trustprobe]", fmt, args);
    va_end(args);
}

const char *trustprobe_state_name(check_state_t state) {
    switch (state) {
    case CHECK_OK:
        return "OK";
    case CHECK_WARN:
        return "WARN";
    case CHECK_FAIL:
        return "FAIL";
    case CHECK_SKIP:
        return "SKIP";
    }
    return "UNKNOWN";
}

static const char *strip_subgroup_prefix(const char *name, const char *subgroup_name) {
    size_t prefix_len = strlen(subgroup_name);
    if (strlen(name) <= prefix_len) return name;
    for (size_t i = 0; i < prefix_len; i++) {
        if (tolower((unsigned char)name[i]) != tolower((unsigned char)subgroup_name[i]))
            return name;
    }
    if (name[prefix_len] != ' ') return name;
    return name + prefix_len + 1;
}

static void print_result_line(const char *display_name, const check_result_t *result) {
    static const char *state_labels[] = {"ok  ", "warn", "fail", "skip"};
    const char *label = (unsigned)result->state < 4
        ? state_labels[result->state] : "????";
    fprintf(stdout, "      %s%s%s  %s",
        state_color(result->state), label, c_reset(),
        display_name);
    if (result->detail[0] != '\0') {
        fprintf(stdout, "  %s", result->detail);
    }
    if (result->requires_root) {
        fprintf(stdout, "  (requires root)");
    }
    fputc('\n', stdout);
}

static void trustprobe_print_result_in_subgroup(const check_result_t *result,
                                             const char *subgroup_name) {
    print_result_line(strip_subgroup_prefix(result->name, subgroup_name), result);
}

void trustprobe_summary_add(posture_summary_t *summary, const check_result_t *result) {
    switch (result->state) {
    case CHECK_OK:
        summary->ok_count++;
        break;
    case CHECK_WARN:
        summary->warn_count++;
        break;
    case CHECK_FAIL:
        summary->fail_count++;
        break;
    case CHECK_SKIP:
        summary->skip_count++;
        break;
    }
}

check_state_t trustprobe_summary_state(const posture_summary_t *summary) {
    if (summary->fail_count > 0) {
        return CHECK_FAIL;
    }
    if (summary->warn_count > 0) {
        return CHECK_WARN;
    }
    if (summary->ok_count > 0) {
        return CHECK_OK;
    }
    return CHECK_SKIP;
}

static void trustprobe_print_summary(const char *name, const posture_summary_t *summary) {
    static const char *names[] = {"ok", "warn", "fail", "skip"};
    check_state_t state = trustprobe_summary_state(summary);
    const char *sname = (unsigned)state < 4 ? names[state] : "unknown";
    printf(
        "  %s%s%s  %s%s:%s  %zu ok  %zu warn  %zu fail  %zu skip\n",
        c_accent(), name, c_reset(),
        state_color(state), sname, c_reset(),
        summary->ok_count, summary->warn_count,
        summary->fail_count, summary->skip_count
    );
}

static void print_json_string(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (*p < 0x20) {
                printf("\\u%04x", *p);
            } else {
                putchar(*p);
            }
            break;
        }
    }
    putchar('"');
}

static void print_json_summary(const posture_summary_t *summary) {
    printf("{\"state\":");
    print_json_string(trustprobe_state_name(trustprobe_summary_state(summary)));
    printf(
        ",\"counts\":{\"ok\":%zu,\"warn\":%zu,\"fail\":%zu,\"skip\":%zu}}",
        summary->ok_count, summary->warn_count,
        summary->fail_count, summary->skip_count
    );
}

static const char *exit_meaning(int exit_code) {
    switch (exit_code) {
    case 0:
        return "no_fail";
    case 1:
        return "posture_fail";
    case 2:
        return "usage_error";
    default:
        return "unknown";
    }
}

static void trustprobe_print_json(
    const char *mode,
    const char *banner,
    const trustprobe_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
) {
    printf("{\"mode\":");
    print_json_string(mode);
    printf(",\"banner\":");
    print_json_string(banner);
    printf(",\"groups\":[");

    for (size_t i = 0; i < group_count; i++) {
        if (i > 0) {
            putchar(',');
        }
        printf("{\"name\":");
        print_json_string(groups[i].name);
        printf(",\"summary\":");
        print_json_summary(groups[i].summary);
        printf(",\"subgroups\":[");
        for (size_t s = 0; s < groups[i].subgroup_count; s++) {
            const check_subgroup_t *sg = &groups[i].subgroups[s];
            if (s > 0) {
                putchar(',');
            }
            printf("{\"name\":");
            print_json_string(sg->name);
            printf(",\"summary\":");
            print_json_summary(&sg->summary);
            printf(",\"results\":[");
            for (size_t j = 0; j < sg->result_count; j++) {
                const check_result_t *result = &sg->results[j];
                if (j > 0) {
                    putchar(',');
                }
                printf("{\"name\":");
                print_json_string(result->name);
                printf(",\"state\":");
                print_json_string(trustprobe_state_name(result->state));
                printf(",\"detail\":");
                print_json_string(result->detail);
                printf(",\"requires_root\":%s}", result->requires_root ? "true" : "false");
            }
            printf("]}");
        }
        printf("]}");
    }

    printf("],\"overall\":");
    print_json_summary(overall);
    printf(",\"exit_code\":%d,\"exit_meaning\":", exit_code);
    print_json_string(exit_meaning(exit_code));
    printf("}\n");
}

static void print_groups_hierarchy(
    const trustprobe_group_view_t *groups,
    size_t group_count
) {
    for (size_t g = 0; g < group_count; g++) {
        fprintf(stdout, "  %s%s%s\n", c_blue(), groups[g].name, c_reset());
        putchar('\n');
        for (size_t s = 0; s < groups[g].subgroup_count; s++) {
            const check_subgroup_t *sg = &groups[g].subgroups[s];
            if (sg->result_count == 0) continue;
            printf("    %s%s%s\n", c_accent(), sg->name, c_reset());
            for (size_t i = 0; i < sg->result_count; i++) {
                trustprobe_print_result_in_subgroup(&sg->results[i], sg->name);
            }
            putchar('\n');
        }
        trustprobe_print_summary(groups[g].name, groups[g].summary);
        putchar('\n');
    }
}

static void trustprobe_print_plain(
    const char *banner,
    const trustprobe_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall
) {
    static const char *snames[] = {"ok", "warn", "fail", "skip"};
    check_state_t ost = trustprobe_summary_state(overall);
    trustprobe_log("%s", banner);
    putchar('\n');
    printf("  %soverall%s  %s%s:%s  %zu ok  %zu warn  %zu fail  %zu skip\n\n",
        c_brand(), c_reset(),
        state_color(ost), (unsigned)ost < 4 ? snames[ost] : "unknown", c_reset(),
        overall->ok_count, overall->warn_count,
        overall->fail_count, overall->skip_count);
    print_groups_hierarchy(groups, group_count);
}

void trustprobe_render(
    trustprobe_render_mode_t mode,
    const char *mode_str,
    const char *banner,
    const trustprobe_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
) {
    if (mode == TRUSTPROBE_RENDER_JSON) {
        trustprobe_print_json(mode_str, banner, groups, group_count, overall, exit_code);
    } else {
        trustprobe_print_plain(banner, groups, group_count, overall);
    }
}
