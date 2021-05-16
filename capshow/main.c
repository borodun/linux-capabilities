#include <sys/types.h>
#include <sys/capability.h>
#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int readable = 0;
char fieldNames[8][20] = {{"NAME"},
                          {"PID"},
                          {"TID"},
                          {"INHERITABLE"},
                          {"PERMITTED"},
                          {"EFFECTIVE"},
                          {"BOUNDING"},
                          {"AMBIENT"}};

void printReadable(char *capNum) {
    unsigned long long value;
    unsigned cap;
    const char *sep = "";

    value = strtoull(capNum, NULL, 16);
    printf("0x%016llx=", value);

    if (!memcmp("0000003fffffffff", capNum, 16)) {
        printf("all\n");
        return;
    }
    if (!memcmp("0000000000000000", capNum, 16)) {
        printf("none\n");
        return;
    }

    for (cap = 0; (cap < 64) && (value >> cap); ++cap) {
        if (value & (1ULL << cap)) {
            char *ptr;

            ptr = cap_to_name(cap);
            if (ptr != NULL) {
                printf("%s%s", sep, ptr);
                cap_free(ptr);
            } else {
                printf("%s%u", sep, cap);
            }
            sep = ",";
        }
    }
    printf("\n");
}

int processFile(char *p, int pid, int tid) {
    const int fieldCount = 6;
    char keys[6][10] = {{"Name:"},
                        {"CapInh:"},
                        {"CapPrm:"},
                        {"CapEff:"},
                        {"CapBnd:"},
                        {"CapAmb:"}};
    char values[fieldCount][20];
    for (int i = 0; i < fieldCount; ++i) {
        char *ptr = strstr(p, keys[i]);
        ptr += strlen(keys[i]) + 1; // + 1 to skip \t
        int j;
        for (j = 0; j < 19 && *ptr != '\n'; ++j, ++ptr) {
            values[i][j] = *ptr;
        }
        values[i][j] = '\0';
    }

    printf("%20s %6d %-6d 0x%-18s 0x%-18s 0x%-18s 0x%-18s 0x%-18s\n", values[0], pid,
           tid, values[1], values[2], values[3], values[4], values[5]);

    if (readable) {
        for (int i = 3; i < 8; ++i) {
            printf("%12s ", fieldNames[i]);
            printReadable(values[i - 2]);
        }
        printf("\n");
    }
    return 1;
}

int isPidFolder(const struct dirent *entry) {
    const char *p;
    for (p = entry->d_name; *p; p++) {
        if (!isdigit(*p)) {
            return 0;
        }
    }
    return 1;
}

int printCaps(int pid) {
    DIR *threadDir;
    struct dirent *entry;
    char dirName[50];
    snprintf(dirName, sizeof(dirName), "/proc/%d/task", pid);

    char error[100];
    threadDir = opendir(dirName);
    if (!threadDir) {
        snprintf(error, sizeof(error), "Error with opening /proc/%d/task folder", pid);
        perror(error);
        return 1;
    }

    while ((entry = readdir(threadDir))) {
        if (!isPidFolder(entry)) {
            continue;
        }
        int tid = atoi(entry->d_name);

        char capPath[50];
        snprintf(capPath, sizeof(capPath), "/proc/%d/task/%d/status", tid, tid);

        int fd;
        if ((fd = open(capPath, O_RDONLY)) == -1) {
            snprintf(error, sizeof(error), "Error with opening %s", capPath);
            perror(error);
            return 0;
        }

        int fileSize = 1500;
        char *file = malloc(fileSize * sizeof(char));
        if (file == NULL) {
            printf("Error with malloc\n");
            close(fd);
            return 0;
        }

        int n = read(fd, file, fileSize);
        if (n == -1) {
            perror("Error while reading file");
        }
        processFile(file, pid, tid);

        free(file);
        close(fd);
    }

    return 1;
}

int main(int argc, char *argv[]) {
    int pid = 0;
    for (int optIdx = 1; optIdx < argc; ++optIdx) {
        if (argv[optIdx][0] == '-') {
            switch (argv[optIdx][1]) {
                case 'p':
                    pid = atoi(argv[optIdx + 1]);
                    continue;
                case 'r':
                    readable = 1;
                    continue;
                case 'h':
                default:
                    printf("Usage: %s [-p pid] [-r] \n", argv[0]);
                    return -1;
            }
        }
    }


    printf("%20s %6s %-6s %-20s %-20s %-20s %-20s %-20s\n", fieldNames[0], fieldNames[1],
           fieldNames[2], fieldNames[3], fieldNames[4], fieldNames[5], fieldNames[6], fieldNames[7]);

    if (pid != 0) {
        printCaps(pid);
        return 0;
    }

    DIR *procDir;
    struct dirent *entry;
    procDir = opendir("/proc");
    if (!procDir) {
        perror("Error with opening /proc");
        return 1;
    }

    while ((entry = readdir(procDir))) {
        if (!isPidFolder(entry)) {
            continue;
        }
        int pid = atoi(entry->d_name);
        printCaps(pid);
    }

    closedir(procDir);
    return 0;
}