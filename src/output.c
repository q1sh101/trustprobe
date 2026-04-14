#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "output.h"

/* --- colors (single source of truth) --- */

static bool use_color(void) {
    static int cached = -1;
    if (cached < 0) {
        cached = isatty(fileno(stdout)) != 0;
    }
    return cached != 0;
}

static const char *c_reset(void) { return use_color() ? "\033[0m" : ""; }
static const char *c_blue(void) { return use_color() ? "\033[1;34m" : ""; }
static const char *c_green(void) { return use_color() ? "\033[32m" : ""; }
static const char *c_yellow(void) { return use_color() ? "\033[33m" : ""; }
static const char *c_red(void) { return use_color() ? "\033[31m" : ""; }
static const char *c_dim(void) { return use_color() ? "\033[2;37m" : ""; }

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

/* --- logging --- */

static void vprint_prefixed(FILE *stream, const char *color, const char *label, const char *fmt, va_list args) {
    fprintf(stream, "  %s%s%s ", color, label, c_reset());
    vfprintf(stream, fmt, args);
    fputc('\n', stream);
}

void trustprobe_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprint_prefixed(stdout, c_blue(), "[trustprobe]", fmt, args);
    va_end(args);
}

/* --- state names --- */

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

/* --- result formatting --- */

static void print_result_label(FILE *stream, check_state_t state) {
    static const char *labels[] = {"  ok ", " warn", " fail", " skip"};
    const char *label = (unsigned)state < 4 ? labels[state] : " ????";
    fprintf(stream, "  %s[%s]%s", state_color(state), label, c_reset());
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
        summary->ok_count,
        summary->warn_count,
        summary->fail_count,
        summary->skip_count
    );
}

static const char *exit_meaning(int exit_code) {
    switch (exit_code) {
    case 0:
        return "no_fail";
    case 1:
        return "posture_fail";
    case 2:
        return "usage_or_runtime_error";
    default:
        return "unknown";
    }
}

void trustprobe_print_result(const check_result_t *result) {
    FILE *stream = stdout;
    print_result_label(stream, result->state);
    fprintf(stream, " %s", result->name);
    if (result->detail[0] != '\0') {
        fprintf(stream, "  %s", result->detail);
    }
    if (result->requires_root) {
        fprintf(stream, "  (requires root)");
    }
    fputc('\n', stream);
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

void trustprobe_print_summary(const char *name, const posture_summary_t *summary) {
    check_state_t state = trustprobe_summary_state(summary);
    const char *color = state_color(state);
    const char *reset = c_reset();

    printf(
        "  %s: %s%s%s  %zu OK / %zu WARN / %zu FAIL / %zu SKIP\n",
        name,
        color,
        trustprobe_state_name(state),
        reset,
        summary->ok_count,
        summary->warn_count,
        summary->fail_count,
        summary->skip_count
    );
}

void trustprobe_print_json(
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
        printf(",\"results\":[");

        for (size_t j = 0; j < groups[i].result_count; j++) {
            const check_result_t *result = &groups[i].results[j];
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

    printf("],\"overall\":");
    print_json_summary(overall);
    printf(",\"exit_code\":%d,\"exit_meaning\":", exit_code);
    print_json_string(exit_meaning(exit_code));
    printf("}\n");
}
