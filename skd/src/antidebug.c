/*
 * First proof of concept of antidebugging techniques.
 */

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"
#include "../include/common.h"
#include "antidebug.h"

int antidebug_sigtrap_var = 0;
void antidebug_sigtrap_handler(int n) {
	antidebug_sigtrap_var++;
}

// Check that nobody is tracing us
__inline__ void antidebug_trace() {
    int status;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        debug("Antidebug1 reached!\n");
        exit(0);
    }
    waitpid(-1, &status,0);
    exit(1);
}

// Test for another fd opened and variable "_" modified
__inline__ void antidebug_morefds(char *argv0) {
    // No more fd opened
    if( close(3) != -1) {
        exit(0);
    }

    // Var _ not modified
    if(strcmp(argv0, (char *)getenv("_"))) {
        exit(0);
    }
}

// Checksum the functions in memory and check that they are not modified.
// If a breakpoint is added, then the checksum will fail.


