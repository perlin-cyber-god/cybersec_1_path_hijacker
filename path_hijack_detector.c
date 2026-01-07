#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>

// Professional Terminal Colors
#define RED   "\x1B[31m"
#define YEL   "\x1B[33m"
#define GRN   "\x1B[32m"
#define CYN   "\x1B[36m"
#define RESET "\x1B[0m"

// Inotify buffer sizing
#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))

/**
 * PHASE 1 & 2: Audit and Register Watches
 */
void run_audit(int inotify_fd, char *path_env, int *watch_count) {
    char *start = path_env;
    char *end;

    while (1) {
        end = strchr(start, ':');
        char dir[512] = {0};
        
        // Handle tokenization with pointer arithmetic
        if (end == NULL) {
            strncpy(dir, start, 511);
        } else {
            size_t length = end - start;
            if (length > 0) {
                strncpy(dir, start, (length < 511) ? length : 511);
            }
        }

        // Check for the "Empty Path/CWD" vulnerability
        if (dir[0] == '\0' || strcmp(dir, ".") == 0) {
            printf(RED "[!] CRITICAL: Current Working Directory (CWD) is in PATH!" RESET "\n");
            printf("    Risk: Shell will execute local files before system commands.\n\n");
        } else {
            struct stat st;
            // syscall: stat() to bridge to Kernel metadata
            if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
                printf("[*] Auditing: %s\n", dir);
                
                // Security Check: World Writable
                if (st.st_mode & S_IWOTH) {
                    // Security Check: The Sticky Bit (The Mitigation)
                    if (st.st_mode & S_ISVTX) {
                        printf(CYN "    [+] World-writable + Sticky Bit (Lower Risk)" RESET "\n");
                    } else {
                        printf(RED "    [!!!] DANGER: World-writable! Adding Active Watch..." RESET "\n");
                        // Register this folder with the Kernel Sentry
                        if (inotify_add_watch(inotify_fd, dir, IN_CREATE) != -1) {
                            (*watch_count)++;
                        }
                    }
                }
                // Security Check: Ownership
                if (st.st_uid != 0) {
                    printf(YEL "    [!] NOTICE: Non-root owner (UID: %d)" RESET "\n", st.st_uid);
                }
            }
        }

        if (end == NULL) break;
        start = end + 1;
    }
}

int main() {
    char *path_env = getenv("PATH");
    if (!path_env) {
        fprintf(stderr, "Fatal: PATH environment variable not found.\n");
        return 1;
    }

    // Initialize the Inotify Kernel Subsystem
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return 1;
    }

    printf(GRN "=== LINUX INTERNAL PATH SECURITY AUDITOR & SENTRY ===" RESET "\n");
    printf("Initial System Audit starting...\n\n");

    int watch_count = 0;
    run_audit(inotify_fd, path_env, &watch_count);

    if (watch_count == 0) {
        printf("\n" GRN "Audit Complete. No high-risk directories found for monitoring." RESET "\n");
        close(inotify_fd);
        return 0;
    }

    // --- PHASE 3: ACTIVE MONITORING (EVENT LOGGING) ---
    printf("\n" GRN "[+] Audit Complete. %d directories under active surveillance..." RESET "\n", watch_count);
    printf("Waiting for filesystem events (Press Ctrl+C to stop)...\n");
    
    char buffer[BUF_LEN];
    while (1) {
        // This read() blocks until the Kernel pushes an event
        int length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            
            // Mask check: Was a new file created?
            if (event->len > 0 && (event->mask & IN_CREATE)) {
                printf(RED "\n[SECURITY ALERT]" RESET " New file created in PATH directory!\n");
                printf("  Filename: " YEL "%s" RESET "\n", event->name);
                printf("  Warning: This file could hijack system commands.\n");
            }
            
            // Advance the pointer by the size of the event + the variable name length
            i += EVENT_SIZE + event->len;
        }
    }

    close(inotify_fd);
    return 0;
}
