
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#define MAX_TRANSFER 4096

static int game_cmdline(pid_t pid) {
    char path[64], buf[8192];
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    for (ssize_t i = 0; i < n;) {
        size_t len = strnlen(buf + i, (size_t)(n - i));
        for (size_t j = 0; j + 12 <= len; ++j)
            if (strncasecmp(buf + i + j, "rabiribi.exe", 12) == 0)
                return 1;
        i += (ssize_t)len + 1;
    }
    return 0;
}

static int same_uid(pid_t pid, uid_t uid) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long real_uid;
        if (strncmp(line, "Uid:", 4) == 0) {
            ok = sscanf(line + 4, "%lu", &real_uid) == 1
                 && real_uid == (unsigned long)uid;
            break;
        }
    }
    fclose(f);
    return ok;
}

static int game_mapping(pid_t pid) {
    char path[64], line[8192], mapped[4096];
    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end, offset;
        char perms[5], device[32];
        unsigned long inode;
        mapped[0] = '\0';

        int fields = sscanf(
            line,
            "%llx-%llx %4s %llx %31s %lu %4095[^\n]",
            &start, &end, perms, &offset,
            device, &inode, mapped
        );
        if (fields != 7 || offset != 0) continue;

        char *p = mapped;
        while (*p == ' ' || *p == '\t') ++p;
        size_t n = strlen(p);
        while (n && (p[n - 1] == ' ' || p[n - 1] == '\t'))
            p[--n] = '\0';

        if (n >= 12 && strcasecmp(p + n - 12, "rabiribi.exe") == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int permitted_range(pid_t pid, unsigned long long addr,
                           size_t len, int writing) {
    if (!len || len > MAX_TRANSFER || addr > ULLONG_MAX - len)
        return 0;

    char path[64], line[8192], perms[5];
    unsigned long long start, end;
    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3)
            continue;
        if (addr >= start && addr + len <= end &&
            perms[0] == 'r' && (!writing || perms[1] == 'w')) {
            ok = 1;
            break;
        }
    }
    fclose(f);
    return ok;
}

int main(int argc, char **argv) {
    if (geteuid() != 0 || argc != 2) {
        fprintf(stderr, "Must be launched through sudo with a PID.\n");
        return 2;
    }

    const char *sudo_uid = getenv("SUDO_UID");
    char *uid_end = NULL;
    errno = 0;
    unsigned long invoking_uid = sudo_uid
        ? strtoul(sudo_uid, &uid_end, 10)
        : ULONG_MAX;

    if (errno || !sudo_uid || !*sudo_uid ||
        !uid_end || *uid_end || invoking_uid == 0 ||
        invoking_uid > UINT_MAX) {
        fprintf(stderr, "Missing or invalid SUDO_UID.\n");
        return 2;
    }

    char *end = NULL;
    long p = strtol(argv[1], &end, 10);
    if (!end || *end || p <= 1 || p > INT_MAX) {
        fprintf(stderr, "Invalid PID.\n");
        return 2;
    }
    pid_t pid = (pid_t)p;

    if (!same_uid(pid, (uid_t)invoking_uid) ||
        !game_cmdline(pid) || !game_mapping(pid)) {
        fprintf(stderr, "Target rejected: not this user's Rabi-Ribi process.\n");
        return 2;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/mem", (long)pid);
    int mem = open(path, O_RDWR | O_CLOEXEC);
    if (mem < 0) {
        perror("open target memory");
        return 2;
    }

    char *line = NULL;
    size_t capacity = 0;
    puts("READY");
    fflush(stdout);

    while (getline(&line, &capacity, stdin) != -1) {
        char op;
        unsigned long long addr;
        size_t len;

        if (sscanf(line, " %c", &op) != 1) {
            puts("ERR bad-command");
            fflush(stdout);
            continue;
        }

        if (op == 'Q') {
            puts("OK");
            fflush(stdout);
            break;
        }

        if (op == 'R') {
            char extra;
            if (sscanf(line, " R %llx %zu %c", &addr, &len, &extra) != 2 ||
                !permitted_range(pid, addr, len, 0)) {
                puts("ERR invalid-read");
                fflush(stdout);
                continue;
            }

            unsigned char data[MAX_TRANSFER];
            if (pread(mem, data, len, (off_t)addr) != (ssize_t)len) {
                puts("ERR read-failed");
                fflush(stdout);
                continue;
            }
            printf("OK ");
            for (size_t i = 0; i < len; ++i)
                printf("%02x", data[i]);
            putchar('\n');
            fflush(stdout);
            continue;
        }

        if (op == 'W') {
            char address_text[32], hex[MAX_TRANSFER * 2 + 2], extra;
            if (sscanf(line, " W %31s %8193s %c",
                       address_text, hex, &extra) != 2) {
                puts("ERR bad-write");
                fflush(stdout);
                continue;
            }

            errno = 0;
            addr = strtoull(address_text, &end, 16);
            if (errno || !end || *end) {
                puts("ERR bad-address");
                fflush(stdout);
                continue;
            }

            len = strlen(hex) / 2;
            if (!len || len > MAX_TRANSFER || strlen(hex) != len * 2 ||
                !permitted_range(pid, addr, len, 1)) {
                puts("ERR invalid-write");
                fflush(stdout);
                continue;
            }

            unsigned char data[MAX_TRANSFER];
            int valid = 1;
            for (size_t i = 0; i < len; ++i) {
                unsigned int value;
                if (!isxdigit((unsigned char)hex[2*i]) ||
                    !isxdigit((unsigned char)hex[2*i+1]) ||
                    sscanf(hex + 2*i, "%2x", &value) != 1) {
                    valid = 0;
                    break;
                }
                data[i] = (unsigned char)value;
            }

            if (!valid || pwrite(mem, data, len, (off_t)addr) != (ssize_t)len) {
                puts("ERR write-failed");
                fflush(stdout);
                continue;
            }
            printf("OK %zu\n", len);
            fflush(stdout);
            continue;
        }

        puts("ERR unknown-command");
        fflush(stdout);
    }

    free(line);
    close(mem);
    return 0;
}
