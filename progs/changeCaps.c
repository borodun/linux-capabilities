#include <stdlib.h>
#include <stdio.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <string.h>

const char *capNames[CAP_LAST_CAP + 1] = {
        "cap_chown",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_fowner",
        "cap_fsetid",
        "cap_kill",
        "cap_setgid",
        "cap_setuid",
        "cap_setpcap",
        "cap_linux_immutable",
        "cap_net_bind_service",
        "cap_net_broadcast",
        "cap_net_admin",
        "cap_net_raw",
        "cap_ipc_lock",
        "cap_ipc_owner",
        "cap_sys_module",
        "cap_sys_rawio",
        "cap_sys_chroot",
        "cap_sys_ptrace",
        "cap_sys_pacct",
        "cap_sys_admin",
        "cap_sys_boot",
        "cap_sys_nice",
        "cap_sys_resource",
        "cap_sys_time",
        "cap_sys_tty_config",
        "cap_mknod",
        "cap_lease",
        "cap_audit_write",
        "cap_audit_control",
        "cap_setfcap",
        "cap_mac_override",
        "cap_mac_admin",
        "cap_syslog"
};

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
    if (argc < 4) {
        printf("Usage: ./set_ambient -p pid +/-cap ...\n");
        return -1;
    }

    int pid;
    int optIdx;
    for (optIdx = 1; optIdx < argc; ++optIdx) {
        if (!memcmp("-p", argv[optIdx], 2)) {
            pid = atoi(argv[++optIdx]);
            capng_setpid(pid);
            ++optIdx;
            break;
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
