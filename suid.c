#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

#define MAX_PATH 4096
#define BUFFER_SIZE 4096

int is_suid(const char *path) {
        struct stat st;
        if (stat(path, &st) == 0) {
                return (st.st_mode & S_ISUID) && (st.st_mode & S_IXUSR);
        }

        return 0;
}

int check_for_relative_paths(const char *filepath) 
{
        FILE *fp;
        char command[MAX_PATH + 50];
        char buffer[BUFFER_SIZE];
        int vuln = 0;

        snprintf(command, sizeof(command), "strings '%s'", filepath);
        fp = popen(command, "r");
        if (fp == NULL) {
                return 0;
        }

        const char *danger_commands[] = {
                "cat", "date", "ls", "echo", "cp", "mv",
                "vim", "nano", "less", "more", "sed", "awk",
                "grep", "find", "service", NULL
        };

        while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
                buffer[strcspn(buffer, "\n")] = 0;
                
                for (size_t i = 0; danger_commands[i] != NULL; i++) {
                        if (strcmp(buffer, danger_commands[i]) == 0) {
                                vuln = 1;
                                printf("   [!] Found potential realtive path: %s\n", danger_commands[i]);
                        }
                }
        }

        pclose(fp);
        return vuln;
}

void scan_directory(const char *dirname)
{
        DIR *dir;
        struct dirent *entry;
        char path[MAX_PATH];

        dir = opendir(dirname);
        if (dir == NULL) {
                return;
        }

        while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                        continue;
                }

                snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);

                if (entry->d_type == DT_REG && is_suid(path)) {
                        printf("\n[+] Found SUID binary: %s\n", path);

                        struct stat st;
                        struct passwd *pw;
                        if (stat(path, &st) == 0) {
                                pw = getpwuid(st.st_uid);
                                if (pw != NULL) {
                                        printf("   Owner: %s\n", pw->pw_name);
                                }
                        }

                        if (check_for_relative_paths(path)) {
                                printf("   [WARNING] This binary might be vulnerable to PATH manipulation!\n");
                        }
                } else if (entry->d_type == DT_DIR) {
                        scan_directory(path);
                }
        }

        closedir(dir);
}

int main()
{
        scan_directory("/");
}
