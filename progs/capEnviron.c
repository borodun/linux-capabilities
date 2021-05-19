#include <stdlib.h>
#include <stdio.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <linux/securebits.h>
#include <string.h>
#include <wait.h>

int createCapabilityEnvironment(const int *caps, int capsAmount) {
    capng_get_caps_process();
    capng_clear(CAPNG_SELECT_BOTH);
    if (capng_update(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET, CAP_SETPCAP) == -1) {
        printf("Cannot add cap\n");
        return -1;
    }
    for (int i = 0; i < capsAmount; ++i) {
        int cap = caps[i];
        if (capng_update(CAPNG_ADD, CAPNG_INHERITABLE | CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET, cap) ==
            -1) {
            printf("Cannot add %s to caps\n", capng_capability_to_name(cap));
            return -1;
        }
    }
    int ret = capng_apply(CAPNG_SELECT_BOTH);
    if (ret < 0) {
        printf("capng_apply failed to apply caps with return value %d\n", ret);
        return -1;
    }

    printf("Inheritable: %s \n", capng_print_caps_text(CAPNG_PRINT_BUFFER, CAPNG_INHERITABLE));
    printf("Permitted: %s \n", capng_print_caps_text(CAPNG_PRINT_BUFFER, CAPNG_PERMITTED));
    printf("Effective: %s \n", capng_print_caps_text(CAPNG_PRINT_BUFFER, CAPNG_EFFECTIVE));
    printf("Bounding: %s \n", capng_print_caps_text(CAPNG_PRINT_BUFFER, CAPNG_BOUNDING_SET));

    for (int i = 0; i < capsAmount; ++i) {
        int cap = caps[i];
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) {
            char error[50];
            snprintf(error, sizeof(error), "Cannot set %s as ambient cap", capng_capability_to_name(cap));
            perror(error);
            return -1;
        }
    }

    printf("%d\n", prctl(PR_GET_SECUREBITS));
    if (prctl(PR_SET_SECUREBITS,
              SECBIT_KEEP_CAPS_LOCKED |
              SECBIT_NO_SETUID_FIXUP |
              SECBIT_NO_SETUID_FIXUP_LOCKED |
              SECBIT_NOROOT |
              SECBIT_NOROOT_LOCKED) != 0) {
        perror("Cannot set secure bits");
        return -1;
    }
    printf("%d\n", prctl(PR_GET_SECUREBITS));
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [allowed capabilities] -p prog_path prog_args", argv[0]);
        return 0;
    }

    int capsArgsBorder;
    int i = 0;
    while (memcmp("-p", argv[i], 2) != 0) {
        ++i;
    }
    capsArgsBorder = i;
    if (capsArgsBorder != 1) {
        int capsAmount = 0;
        int caps[capsArgsBorder - 1];
        for (i = 1; i < capsArgsBorder; ++i) {
            int cap = capng_name_to_capability(argv[i]);
            if (cap == -1) {
                printf("No such capability: %s\n", argv[i]);
                continue;
            }
            caps[i - 1] = cap;
            ++capsAmount;
        }

        if (createCapabilityEnvironment(caps, capsAmount) == -1) {
            return -1;
        }
    }

    pid_t child;
    if ((child = fork()) == 0) {
        execvp(argv[capsArgsBorder + 1], &argv[capsArgsBorder + 1]);
        perror("Error occurred when trying to execute a program");
        return -1;
    } else if (child == -1) {
        perror("Error occurred when trying to fork a process");
        return -1;
    }
    printf("Waiting for child with pid %d\n", child);

    int status;
    child = wait(&status);
    if (child == -1) {
        perror("Error occurred while waiting for child death");
        return -1;
    }
    if (WIFEXITED(status)) {
        printf("Exit status of child with pid %d: %d\n", child, WEXITSTATUS(status));
    } else {
        printf("Child %d exited incorrectly\n", child);
    }
    return 0;
}
