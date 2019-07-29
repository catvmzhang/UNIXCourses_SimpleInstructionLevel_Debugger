#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include "myelf.h"


void show_elf_info(struct elf_t *self){
	LOGD("[INFO] is dynamic: %d\n", self->isDynamic);
	printf("** program '%s' loaded. entry point 0x%08lx,vaddr 0x%08lx, offset 0x%02lx, size 0x%02lx\n",
			self->name, self->entry, self->text_addr, self->text_offset, self->text_size);	
}

void show_elf_text_range(struct elf_t *self){
	char chmod[4];
	memset(chmod, '-', 4);

	if((self->text_flag & 0b0001) == 0b0001) chmod[0] = 'r'; 
	if((self->text_flag & 0b0010) == 0b0010) chmod[1] = 'w'; 
	if((self->text_flag & 0b0100) == 0b0100) chmod[2] = 'x'; 
	chmod[3] = '\0';

	printf("%016lx-%016lx %s %02lx\t%s\n", self->text_addr, self->text_addr+self->text_size, 
			  chmod, self->text_offset, self->name);
}

int elf_check(char *name, int *type){
	char magic[5];

	FILE *file = fopen(name, "rb");
	if(file){
		fread(&magic, 5, sizeof(char), file);
		fclose(file);
		if(magic[0]==0x7f && magic[1]=='E' && magic[2]=='L' && magic[3]=='F' ){
			if(magic[4] == 0x02) *type = ELF64;
			else *type = ELF32;

			return OPEN_SUCC;
		}else return NOT_ELF;
	}else return OPEN_FAIL;	
}

void elf_init(struct elf_t **self, char *name, int type){
	(*self) = (struct elf_t*)malloc(sizeof(struct elf_t));
	(*self)->name = (char*)malloc(sizeof(char) * strlen(name));
	strcpy((*self)->name, name);

	if(type == ELF64){
		struct elf64_t elf64;
		elf64_init(&elf64, name);
		elf64_findtextHeader(&elf64);
		elf64_gettextSection(&elf64);
		elf64_assign((*self), &elf64);
	}else{
		struct elf32_t elf32;
		elf32_init(&elf32, name);
		elf32_findtextHeader(&elf32);
		elf32_gettextSection(&elf32);
		elf32_assign((*self), &elf32);	
	}
}

void elf64_init(struct elf64_t *elf, char* name){
	FILE *file = fopen(name, "rb");
	elf->file = file;
	//header
	fread(&(elf->header), 1, sizeof(Elf64_Ehdr), file);


	//str section header
	int strSectionHeaderOffset = elf->header.e_shoff + (elf->header.e_shstrndx)*sizeof(Elf64_Shdr);
	fseek(file, strSectionHeaderOffset, SEEK_SET);
	fread(&(elf->strHeader), 1, sizeof(Elf64_Shdr), file);

	LOGD("size:%lx\n", elf->strHeader.sh_size);
	LOGD("offset: %lx\n", elf->strHeader.sh_offset);
	//read str table in str section
	fseek(file, elf->strHeader.sh_offset, SEEK_SET);
	fread(elf->strtab, elf->strHeader.sh_size, sizeof(char), file);
}

void elf64_findtextHeader(struct elf64_t *elf){
	Elf64_Shdr tempHeader;
	//find .text header
	fseek(elf->file, elf->header.e_shoff, SEEK_SET);
	for(int i=0;i<elf->header.e_shnum;i++){
		fread(&tempHeader, 1, sizeof(Elf64_Shdr), elf->file);	
		if(strcmp((elf->strtab + tempHeader.sh_name), ".text") == 0){
			elf->textHeader = tempHeader;
			break;
		}
	}

	Elf64_Phdr pHeader;
	//find .text in thich segment
	fseek(elf->file, elf->header.e_phoff, SEEK_SET);
	for(int i=0;i<elf->header.e_phnum;i++){
		fread(&pHeader, 1, sizeof(Elf64_Phdr), elf->file);
		if(pHeader.p_vaddr <= elf->textHeader.sh_addr && 
				pHeader.p_vaddr+pHeader.p_memsz > elf->textHeader.sh_addr){
			elf->text_flag = pHeader.p_flags;
		}
	}
}

void elf64_gettextSection(struct elf64_t *elf){
	fseek(elf->file, elf->textHeader.sh_offset, SEEK_SET);
	elf->text_section = (char*)malloc(sizeof(char) * elf->textHeader.sh_size);
	fread(elf->text_section, elf->textHeader.sh_size, sizeof(char), elf->file);
}

void elf64_assign(struct elf_t *self, struct elf64_t *elf){
	self->entry = elf->header.e_entry;
	self->text_addr = elf->textHeader.sh_addr;
	self->text_offset = elf->textHeader.sh_offset;
	self->text_size = elf->textHeader.sh_size;
	self->text_flag = elf->text_flag;
	self->text_section = elf->text_section;
	self->isDynamic = elf->header.e_type==ET_DYN?1:0;
}
//===================================================================================
void elf32_init(struct elf32_t *elf, char* name){
	FILE *file = fopen(name, "rb");
	elf->file = file;
	//header
	fread(&(elf->header), 1, sizeof(Elf32_Ehdr), file);


	//str section header
	int strSectionHeaderOffset = elf->header.e_shoff + (elf->header.e_shstrndx)*sizeof(Elf32_Shdr);
	fseek(file, strSectionHeaderOffset, SEEK_SET);
	fread(&(elf->strHeader), 1, sizeof(Elf64_Shdr), file);

	LOGD("size:%x\n", elf->strHeader.sh_size);
	LOGD("offset: %x\n", elf->strHeader.sh_offset);
	//read str table in str section
	fseek(file, elf->strHeader.sh_offset, SEEK_SET);
	fread(elf->strtab, elf->strHeader.sh_size, sizeof(char), file);
}

void elf32_findtextHeader(struct elf32_t *elf){
	Elf32_Shdr tempHeader;
	
	//find .text header
	fseek(elf->file, elf->header.e_shoff, SEEK_SET);
	for(int i=0;i<elf->header.e_shnum;i++){
		fread(&tempHeader, 1, sizeof(Elf32_Shdr), elf->file);	
		if(strcmp((elf->strtab + tempHeader.sh_name), ".text") == 0){
			elf->textHeader = tempHeader;
			break;
		}
	}	

	Elf32_Phdr pHeader;
	//find .text in thich segment
	fseek(elf->file, elf->header.e_phoff, SEEK_SET);
	for(int i=0;i<elf->header.e_phnum;i++){
		fread(&pHeader, 1, sizeof(Elf32_Phdr), elf->file);
		if(pHeader.p_vaddr <= elf->textHeader.sh_addr && 
				pHeader.p_vaddr+pHeader.p_memsz > elf->textHeader.sh_addr){
			elf->text_flag = pHeader.p_flags;
		}
	}
}

void elf32_gettextSection(struct elf32_t *elf){
	fseek(elf->file, elf->textHeader.sh_offset, SEEK_SET);
	elf->text_section = (char*)malloc(sizeof(char) * elf->textHeader.sh_size);
	fread(elf->text_section, elf->textHeader.sh_size, sizeof(char), elf->file);
}

void elf32_assign(struct elf_t *self, struct elf32_t *elf){
	self->entry = elf->header.e_entry;
	self->text_addr = elf->textHeader.sh_addr;
	self->text_offset = elf->textHeader.sh_offset;
	self->text_size = elf->textHeader.sh_size;
	self->text_flag = elf->text_flag;
	self->text_section = elf->text_section;
	self->isDynamic = elf->header.e_type==ET_DYN?1:0;
}

