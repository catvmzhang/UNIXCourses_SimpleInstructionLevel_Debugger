#define BUFFERSIZE 32

#ifdef DEBUG
	#define LOGD(...) printf(__VA_ARGS__)
#else
	#define LOGD(...) 
#endif

#define HELP_INFO "\
- break {instruction-address}: add a break point\n\
- cont: continue execution\n\
- delete {break-point-id}: remove a break point\n\
- disasm addr: disassemble instructions in a file or a memory region\n\
- dump addr [length]: dump memory content\n\
- exit: terminate the debugger\n\
- get reg: get a single value from a register\n\
- getregs: show registers\n\
- help: show this message\n\
- list: list break points\n\
- load {path/to/a/program}: load a program\n\
- run: run the program\n\
- vmmap: show memory layout\n\
- set reg val: get a single value to a register\n\
- si: step into instruction\n\
- start: start the program and stop at the first instruction\n"


struct pInfo_t{
	pid_t pid;
	char name[64];
	char argv[16][16];
	int terminiated;

	struct breakpointList_t *bplist;
	struct dump_t *dumpinfo;
	struct elf_t *elf;
	struct disasm_t *disasm;
	struct user_regs_struct *regs;
};

struct dump_t{
	unsigned long long dumpAddr;
	char dumpChar[16];
};

struct breakpointList_t{
	unsigned long long address;
	long code;
	struct breakpointList_t *next;
};

int isCmd(char *str, const char *cmd);
int isRuntime(struct pInfo_t *pinfo);
int disasm_textInit(struct pInfo_t *pinfo, char *addr);
void init_start_pinfo(struct pInfo_t *pinfo);

void init_regs(struct user_regs_struct **regs);
int read_regs(struct user_regs_struct *regs, pid_t pid); 
void show_regs(struct user_regs_struct *regs);
void show_reg_by_name(struct user_regs_struct *regs, char *regName);
void set_reg(struct user_regs_struct *regs, char *regName, long regVal, pid_t pid);

void dump_init(struct dump_t **self, char *addr); 
void dump_show(struct dump_t *self, pid_t pid);

void breakpoint_init(struct breakpointList_t **self);
void store_breakpoint(struct breakpointList_t **self, unsigned long long address, long code);
void list_breakpoint(struct breakpointList_t **self);
long get_breakpoint_code(struct breakpointList_t **self, unsigned long long stopaddr);
void recover_breakpoint(struct breakpointList_t **self, int id, pid_t pid);

long disasm_runtime(long addrNum, pid_t pid);
long get_startAddr(pid_t pid);

void init_breakpoint_to_start(struct pInfo_t *pinfo);	
long set_INT3(long relativeAddrPos, struct pInfo_t *pinfo);
