#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime.h"

typedef struct {
    const char *path;
    const char *key;
    const char *expected;
} case_t;

static void assert_value(const char *path, const char *key, const char *expected) {
    char value[256] = {0};

    if (!trustprobe_read_key_value(path, key, value, sizeof(value))) {
        fprintf(stderr, "policy parser failure: key %s not found in %s\n", key, path);
        exit(1);
    }

    if (strcmp(value, expected) != 0) {
        fprintf(
            stderr,
            "policy parser failure: key %s expected [%s], got [%s] in %s\n",
            key,
            expected,
            value,
            path
        );
        exit(1);
    }
}

int main(void) {
    const case_t cases[] = {
        {
            .path = "tests/fixtures/policy/good.conf",
            .key = "ImplicitPolicyTarget",
            .expected = "block",
        },
        {
            .path = "tests/fixtures/policy/good.conf",
            .key = "IPCAllowedGroups",
            .expected = "",
        },
        {
            .path = "tests/fixtures/policy/spaces.conf",
            .key = "PresentDevicePolicy",
            .expected = "apply-policy",
        },
        {
            .path = "tests/fixtures/policy/inline_comment.conf",
            .key = "HidePII",
            .expected = "true",
        },
        {
            .path = "tests/fixtures/policy/inline_comment.conf",
            .key = "IPCAllowedUsers",
            .expected = "root",
        },
        {
            .path = "tests/fixtures/policy/quoted.conf",
            .key = "ImplicitPolicyTarget",
            .expected = "block",
        },
        {
            .path = "tests/fixtures/policy/quoted.conf",
            .key = "IPCAllowedUsers",
            .expected = "root",
        },
        {
            .path = "tests/fixtures/policy/quoted.conf",
            .key = "CommentTest",
            .expected = "USBGuard policy for \\\"Laptop\\\"",
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert_value(cases[i].path, cases[i].key, cases[i].expected);
    }

    {
        char value[256] = {0};
        if (trustprobe_read_key_value("tests/fixtures/policy/good.conf", "MissingKey", value, sizeof(value))) {
            fprintf(stderr, "policy parser failure: unexpected match for MissingKey\n");
            return 1;
        }
    }

    printf("policy parser ok\n");
    return 0;
}
