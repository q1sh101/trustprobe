#ifndef BYTHOS_TEST_HARNESS_H
#define BYTHOS_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static inline void restore_env(const char *name, char *saved_value) {
    if (saved_value != NULL) {
        if (setenv(name, saved_value, 1) != 0) {
            fprintf(stderr, "test harness failure: could not restore %s\n", name);
            free(saved_value);
            exit(1);
        }
        free(saved_value);
        return;
    }

    if (unsetenv(name) != 0) {
        fprintf(stderr, "test harness failure: could not unset %s\n", name);
        exit(1);
    }
}

static inline void write_executable(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        fprintf(stderr, "test harness failure: could not create %s\n", path);
        exit(1);
    }
    if (fputs(text, file) == EOF) {
        fclose(file);
        fprintf(stderr, "test harness failure: could not write %s\n", path);
        exit(1);
    }
    fclose(file);

    if (chmod(path, 0700) != 0) {
        fprintf(stderr, "test harness failure: could not chmod %s\n", path);
        exit(1);
    }
}

#endif
