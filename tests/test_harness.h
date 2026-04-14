#ifndef TRUSTPROBE_TEST_HARNESS_H
#define TRUSTPROBE_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static inline void restore_path(char *saved_path) {
    if (saved_path != NULL) {
        if (setenv("PATH", saved_path, 1) != 0) {
            fprintf(stderr, "test harness failure: could not restore PATH\n");
            free(saved_path);
            exit(1);
        }
        free(saved_path);
        return;
    }

    if (unsetenv("PATH") != 0) {
        fprintf(stderr, "test harness failure: could not unset PATH\n");
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
