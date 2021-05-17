#include <stdlib.h>
#include <stdio.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <string.h>

const char *capNames[CAP_LAST_CAP + 1] = {
        "chown",
        "dac_override",
        "dac_read_search",
        "fowner",
        "fsetid",
        "kill",
        "setgid",
        "setuid",
        "setpcap",
        "linux_immutable",
        "net_bind_service",
        "net_broadcast",
        "net_admin",
        "net_raw",
        "ipc_lock",
        "ipc_owner",
        "sys_module",
        "sys_rawio",
        "sys_chroot",
        "sys_ptrace",
        "sys_pacct",
        "sys_admin",
        "sys_boot",
        "sys_nice",
        "sys_resource",
        "sys_time",
        "sys_tty_config",
        "mknod",
        "lease",
        "audit_write",
        "audit_control",
        "setfcap",
        "mac_override",
        "mac_admin",
        "syslog",
        "wake_alarm",
        "block_suspend",
        "audit_read"};

int dropAmbientCap(int cap) {
    if (capng_update(CAPNG_DROP, CAPNG_INHERITABLE, cap) == -1) {
        printf("Cannot add inheritable cap\n");
        return -1;
    }
    if (capng_apply(CAPNG_SELECT_CAPS) == -1) {
        printf("Cannot apply inheritable cap\n");
        return -1;
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0)) {
        perror("Cannot set cap");
        return -1;
    }
    return 0;
}

int addAmbientCap(int cap) {
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
    int pid;
    int optIdx;
    for (optIdx = 1; optIdx < argc; ++optIdx) {
        if (argv[optIdx][0] == '-') {
            switch (argv[optIdx][1]) {
                case 'p':
                    pid = atoi(argv[optIdx + 1]);
                    capng_setpid(pid);
                    continue;
                case 'l':
                    printf("List of capabilities: \n");
                    for (int i = 0; i < CAP_LAST_CAP + 1; ++i) {
                        printf("\t%s\n", capNames[i]);
                    }
                    continue;
                case 'c':
                    ++optIdx;
                    break;
                case 'h':
                    printf("Usage: %s [-l] -p pid +/-cap ...\n", argv[0]);
                    return 0;
                default:
                    continue;
            }
        }
    }

    int capNameLength = 20;
    char capName[capNameLength];
    int cap;
    for (int i = optIdx; i < argc; ++i) {
        switch (argv[i][0]) {
            case '-':
                strncpy(capName, &argv[i][1], capNameLength);
                cap = capng_name_to_capability(capName);
                if (cap == -1) {
                    printf("No such capability: %s\n", capName);
                    continue;
                }
                dropAmbientCap(cap);
                continue;
            case '+':
                strncpy(capName, &argv[i][1], capNameLength);
                cap = capng_name_to_capability(capName);
                if (cap == -1) {
                    printf("No such capability: %s\n", capName);
                    continue;
                }
                addAmbientCap(cap);
                continue;
            default:
                continue;
        }
    }
    return 0;
}
