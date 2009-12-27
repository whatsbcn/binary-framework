#ifndef ANTIDEBUG_H
#define ANTIDEBUG_H

void antidebug_sigtrap_handler(int n);
extern int antidebug_sigtrap_var;

// Check that nobody is stoling our sigtraps
#if ANTIDEBUG
#define antidebug_sigtrap() \
    signal(SIGTRAP, antidebug_sigtrap_handler); \
    __asm__("int3"); \
    signal(SIGTRAP, SIG_DFL); \
	if (antidebug_sigtrap_var != 1) { \
        debug("antidebug_sigtrap reached!\n"); \
        int segfaultaddr = 0; \
        *(int *)segfaultaddr = 0xdeadfeef; \
    } \
	else antidebug_sigtrap_var = 0; 
#else
#define antidebug_sigtrap()
#endif

// Obfuscate analysis
#if ANTIDEBUG
#define antidebug_obfuscate_analysis(value) \
__asm__("pushl %eax\n" \
        "jmp antidebug1" #value " + 2\n" \
        "antidebug1" #value ":\n" \
        ".short 0x45c7\n" \
        "call reloc" #value "\n" \
        "reloc" #value ":\n" \
        "popl %eax\n"\
        "jmp antidebug2" #value "\n"\
        "antidebug2" #value ":\n"\
        "addl $(data" #value " - reloc" #value " + 4), %eax\n"\
        "jmp *%eax\n" \
        "data" #value ":\n" \
        ".long 0\n" \
        "popl %eax\n" \
        );
#else
#define antidebug_obfuscate_analysis(value) 
#endif

#endif

