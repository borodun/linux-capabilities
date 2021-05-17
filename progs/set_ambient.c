#include <stdlib.h>
#include <stdio.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <wait.h>

int addAmbientCap() {
    int cap = CAP_NET_BIND_SERVICE;
    if (capng_get_caps_process() == -1) {
        printf("Cannot get caps\n");
        return -1;
    }
    capng_clear(CAPNG_SELECT_CAPS);
    if (capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap) == -1) {
        printf("Cannot add inheritable cap\n");
        return -1;
    }
    if (capng_apply(CAPNG_SELECT_CAPS) == -1) {
        printf("Cannot apply inheritable cap\n");
        return -1;
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
        perror("Cannot set cap");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./set_ambient prog_path");
        return -1;
    }

    if (addAmbientCap() == -1) {
        return -1;
    }

    int pid;
    if ((pid = fork()) == 0) {
        execv(argv[1], &argv[1]);
        perror("Error occurred with exec");
        return -1;
    }
    printf("Pid of child: %d\n", pid);

    int status;
    pid = wait(&status);
    if (pid == -1) {
        perror("Error occurred while waiting for child death ");
        return -1;
    }
    if (WIFEXITED(status)) {
        printf("Exit status of child with pid %d: %d\n", pid, WEXITSTATUS(status));
    }
    return 0;
}
