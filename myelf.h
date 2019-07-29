#ifndef MYELF_H
#define MYELF_H
#include <elf.h>

#ifdef DEBUG
	#define LOGD(...) printf(__VA_ARGS__)
#else
	#define LOGD(...) 
#endif

struct elf32_t{
	FILE *file;
	Elf32_Ehdr header;
	Elf32_Shdr strHeader;
	Elf32_Shdr textHeader;
	char strtab[65535];
	long text_flag;
	char *text_section;
};

struct elf64_t{
	FILE *file;
	Elf64_Ehdr header;
	Elf64_Shdr strHeader;
	Elf64_Shdr textHeader;
	char strtab[65535];	
	long text_flag;
	char *text_section;
	
};

struct elf_t{
	char *name;
	unsigned long entry;
	unsigned long text_addr;
	unsigned long text_offset;
	unsigned long text_size;
	long text_flag;
	char *text_section;
	int isDynamic;
};

int elf_check(char *name, int *type);
//ret
#define OPEN_SUCC 0
#define OPEN_FAIL 1
#define NOT_ELF   2
//type
#define ELF32 1
#define ELF64 2
void elf_init(struct elf_t **self, char *name, int type);
void show_elf_info(struct elf_t *self);
void show_elf_text_range(struct elf_t *self);

void elf64_init(struct elf64_t *elf, char* name);
void elf64_findtextHeader(struct elf64_t *elf);
void elf64_gettextSection(struct elf64_t *elf);
void elf64_assign(struct elf_t *self, struct elf64_t *elf);
void elf32_init(struct elf32_t *elf, char* name);
void elf32_findtextHeader(struct elf32_t *elf);
void elf32_gettextSection(struct elf32_t *elf);
void elf32_assign(struct elf_t *self, struct elf32_t *elf);
#endif
