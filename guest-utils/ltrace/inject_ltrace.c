#define LTRACE_PATH "/igloo/utils/ltrace"
#define TTY_PATH "/dev/ttyS0"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) void igloo_start_ltrace(void)
{
	// Don't do anything if the user doesn't want to ltrace
	if (!getenv("IGLOO_LTRACE")) {
		return;
	}

	// Open tty for output
	FILE *tty = fopen(TTY_PATH, "w");
	setlinebuf(tty);

	// Get PID
	pid_t pid = getpid();
	char pid_buf[100];
	sprintf(pid_buf, "%d", pid);

	// Build argv and envp
	char *const argv[] = { LTRACE_PATH, "-p", pid_buf, NULL };
	char *const envp[] = { NULL };

	// Read command name
	char comm[1024];
	sprintf(comm, "/proc/%d/comm", pid);
	FILE *f_comm = fopen(comm, "r");
	fgets(comm, sizeof(comm), f_comm);
	fclose(f_comm);

	// Remove trailing newline
	if (comm[strlen(comm) - 1] == '\n') {
		comm[strlen(comm) - 1] = 0;
	}

	// Don't do anything if the user doesn't want to ltrace this process
	char *excluded_cmds = getenv("IGLOO_LTRACE_EXCLUDED");
	if (excluded_cmds) {
		bool excluded = false;
		excluded_cmds = strdup(excluded_cmds);
		char *tok = strtok(excluded_cmds, ",");
		while (tok) {
			if (!strcmp(tok, comm)) {
				excluded = true;
				break;
			}
			tok = strtok(NULL, ",");
		}
		free(excluded_cmds);
		if (excluded) {
			return;
		}
	}

	if (fork()) {
		// In parent, wait for child to set up tracing and then continue to the
		// main executable code

		sleep(1);
	} else {
		// In child, run ltrace and add PID and command name to output

		// Make pipe for sending ltrace output
		int ltrace_pipe[2];
		pipe(ltrace_pipe);

		if (fork()) {
			// In parent, execute ltrace with stdout and stderr going into the pipe

			dup2(ltrace_pipe[1], 1);
			dup2(ltrace_pipe[1], 2);
			execve(LTRACE_PATH, argv, envp);
			fputs("IGLOO ERROR FAILED EXECUTING LTRACE\n", tty);
			exit(-1);
		} else {
			// In child, read ltrace output, add PID and command name, and write to the tty

			// Small buffer size to make edge cases with long lines more common,
			// making bugs show up early
			char line[10];

			FILE *in = fdopen(ltrace_pipe[0], "r");
			setlinebuf(in);
			for (;;) {
				fgets(line, sizeof(line), in);
				fprintf(tty, "igloo ltrace [pid=%d cmd=%s] %s", pid, comm, line);

				// Keep reading until full line is processed
				while (line[strlen(line) - 1] != '\n') {
					fgets(line, sizeof(line), in);
					fputs(line, tty);
				}
			}
		}
	}
}
