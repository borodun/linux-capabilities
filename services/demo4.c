#include <unistd.h>

int main() {
    if (fork() == 0) {
        nice(-20);
        execl("/bin/sleep", "sleep", "1000", NULL);
    }
    return 0;
}
