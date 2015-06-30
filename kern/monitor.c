// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help",         "Display this list of commands",              mon_help         },
	{ "kerninfo",     "Display information about the kernel",       mon_kerninfo     },
	{ "backtrace",    "Display a backtrace",                        mon_backtrace    },
    { "pagemappings", "Display page mappings for a range of pages", mon_pagemappings },
    { "memconst",     "Converts a memory constant to address",      mon_memconst     },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    uint32_t ebp = read_ebp();
    cprintf("Stack backtrace:\n");
    while( ebp > 0 )
    {
        uint32_t* ref = (uint32_t*) ebp;
        cprintf( 
            "ebp 0x%08x  eip 0x%08x  args 0x%08x 0x%08x 0x%08x 0x%08x\n",
            ebp, ref[1], ref[2], ref[3], ref[4], ref[5]
        );
        struct Eipdebuginfo info;
        int hasInfo = debuginfo_eip( ref[1], &info );
        cprintf( "    %s:%d: ", info.eip_file, info.eip_line );
        int i; 
        for( i = 0; i < info.eip_fn_namelen; ++i )
            cprintf( "%c", info.eip_fn_name[i] );
        cprintf( "+%d (%d)\n", ref[1] - info.eip_fn_addr, info.eip_fn_narg );
        ebp = ref[0];
    }
	return 0;
}

void show_page_details(uintptr_t va)
{
    pte_t * pte = page_table_entry(va);
    if( !pte )
    {
        cprintf("va 0x%08x -> unmapped\n", va);
        return;
    }
    cprintf("va 0x%08x -> pa 0x%08x [", va, PTE_ADDR(*pte));
    int comma = 0;
    if( *pte & PTE_P   ) cprintf_sep(&comma, ",", "P");
    if( *pte & PTE_W   ) cprintf_sep(&comma, ",", "W");
    if( *pte & PTE_U   ) cprintf_sep(&comma, ",", "U");
    if( *pte & PTE_PWT ) cprintf_sep(&comma, ",", "PWT");
    if( *pte & PTE_PCD ) cprintf_sep(&comma, ",", "PCD");
    if( *pte & PTE_A   ) cprintf_sep(&comma, ",", "A");
    if( *pte & PTE_D   ) cprintf_sep(&comma, ",", "D");
    if( *pte & PTE_PS  ) cprintf_sep(&comma, ",", "PS");
    if( *pte & PTE_G   ) cprintf_sep(&comma, ",", "G");
    cprintf("]");
    if( PGNUM(PTE_ADDR(*pte)) >= npages )
        cprintf(" (no physical memory present)");
    cprintf("\n");
}

int
mon_pagemappings(int argc, char **argv, struct Trapframe *tf)
{
    if( argc < 2 )
    {
        cprintf("pagemappings expects at least one argument\n");
        return -1;
    }

    if( argc > 3 )
    {
        cprintf("pagemappings expects at most two arguments\n");
        return -1;
    }

    char *    str_end;
    uintptr_t va_start = (uintptr_t) strtol(argv[1], &str_end, 0);
    if( str_end != strfind(argv[1], '\0') )
    {
        cprintf("pagemappings: expecting number as first argument, could not parse '%s'\n", argv[1]);
        return -1;
    }

    uintptr_t va_end = va_start;
    if( argc == 3 )
    {
        va_end = (uintptr_t) strtol(argv[2], &str_end, 0);
        if( str_end != strfind(argv[2], '\0') )
        {
            cprintf("pagemappings: expecting number as second argument, could not parse '%s'\n", argv[2]);
            return -1;
        }
    }
    
    va_start &= ~0xFFF;//PGMASK;
    va_end   &= ~0xFFF; //PGMASK;
    for(; va_start <= va_end; va_start += PGSIZE)
        show_page_details(va_start);
    return 0;
}

// Convenience function converting a string to the va (using above constants)
int get_va_ref_point(const char * name, uint32_t * va)
{
    if( 0 == strcmp( name, "KERNBASE"   ) ) { *va = KERNBASE;   return 1; }
    if( 0 == strcmp( name, "IOPHYSMEM"  ) ) { *va = IOPHYSMEM;  return 1; }
    if( 0 == strcmp( name, "EXTPHYSMEM" ) ) { *va = EXTPHYSMEM; return 1; }
    if( 0 == strcmp( name, "KSTACKTOP"  ) ) { *va = KSTACKTOP;  return 1; }
    if( 0 == strcmp( name, "KSTKSIZE"   ) ) { *va = KSTKSIZE;   return 1; }
    if( 0 == strcmp( name, "KSTKGAP"    ) ) { *va = KSTKGAP;    return 1; }
    if( 0 == strcmp( name, "MMIOLIM"    ) ) { *va = MMIOLIM;    return 1; }
    if( 0 == strcmp( name, "MMIOBASE"   ) ) { *va = MMIOBASE;   return 1; }
    if( 0 == strcmp( name, "ULIM"       ) ) { *va = ULIM;       return 1; }
    if( 0 == strcmp( name, "UVPT"       ) ) { *va = UVPT;       return 1; }
    if( 0 == strcmp( name, "UPAGES"     ) ) { *va = UPAGES;     return 1; }
    if( 0 == strcmp( name, "UENVS"      ) ) { *va = UENVS;      return 1; }
    if( 0 == strcmp( name, "UTOP"       ) ) { *va = UTOP;       return 1; }
    if( 0 == strcmp( name, "UXSTACKTOP" ) ) { *va = UXSTACKTOP; return 1; }
    if( 0 == strcmp( name, "USTACKTOP"  ) ) { *va = USTACKTOP;  return 1; }
    if( 0 == strcmp( name, "UTEXT"      ) ) { *va = UTEXT;      return 1; }
    if( 0 == strcmp( name, "UTEMP"      ) ) { *va = (uint32_t) UTEMP;      return 1; }
    if( 0 == strcmp( name, "PFTEMP"     ) ) { *va = (uint32_t) PFTEMP;     return 1; }
    if( 0 == strcmp( name, "USTABDATA"  ) ) { *va = USTABDATA;  return 1; }
    return 0;
}

int
mon_memconst(int argc, char **argv, struct Trapframe *tf)
{
    if( 2 != argc )
    {
        cprintf("memconst expects a single argument\n");
        return -1;
    }

    uint32_t va;
    if( get_va_ref_point(argv[1], &va) )
    {
        cprintf("%s: 0x%08x\n", argv[1], va);
        return 0;
    }

    cprintf("memconst: unknown memory constant '%s'\n", argv[1]);
    return -1;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
