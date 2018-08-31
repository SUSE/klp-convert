/*
 * elf.c - ELF access library
 *
 * Adapted from kpatch (https://github.com/dynup/kpatch):
 * Copyright (C) 2013-2016 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"

#define WARN(format, ...) \
	fprintf(stderr, "%s: " format "\n", elf->name, ##__VA_ARGS__)

/*
 * Fallback for systems without this "read, mmaping if possible" cmd.
 */
#ifndef ELF_C_READ_MMAP
#define ELF_C_READ_MMAP ELF_C_READ
#endif

bool is_rela_section(struct section *sec)
{
	return (sec->sh.sh_type == SHT_RELA);
}

struct section *find_section_by_name(struct elf *elf, const char *name)
{
	struct section *sec;

	list_for_each_entry(sec, &elf->sections, list)
		if (!strcmp(sec->name, name))
			return sec;

	return NULL;
}

static struct section *find_section_by_index(struct elf *elf,
					     unsigned int idx)
{
	struct section *sec;

	list_for_each_entry(sec, &elf->sections, list)
		if (sec->idx == idx)
			return sec;

	return NULL;
}

static struct symbol *find_symbol_by_index(struct elf *elf, unsigned int idx)
{
	struct symbol *sym;

	list_for_each_entry(sym, &elf->symbols, list)
		if (sym->idx == idx)
			return sym;

	return NULL;
}

static int read_sections(struct elf *elf)
{
	Elf_Scn *s = NULL;
	struct section *sec;
	size_t shstrndx, sections_nr;
	int i;

	if (elf_getshdrnum(elf->elf, &sections_nr)) {
		perror("elf_getshdrnum");
		return -1;
	}

	if (elf_getshdrstrndx(elf->elf, &shstrndx)) {
		perror("elf_getshdrstrndx");
		return -1;
	}

	for (i = 0; i < sections_nr; i++) {
		sec = malloc(sizeof(*sec));
		if (!sec) {
			perror("malloc");
			return -1;
		}
		memset(sec, 0, sizeof(*sec));

		INIT_LIST_HEAD(&sec->relas);

		list_add_tail(&sec->list, &elf->sections);

		s = elf_getscn(elf->elf, i);
		if (!s) {
			perror("elf_getscn");
			return -1;
		}

		sec->idx = elf_ndxscn(s);

		if (!gelf_getshdr(s, &sec->sh)) {
			perror("gelf_getshdr");
			return -1;
		}

		sec->name = elf_strptr(elf->elf, shstrndx, sec->sh.sh_name);
		if (!sec->name) {
			perror("elf_strptr");
			return -1;
		}

		sec->elf_data = elf_getdata(s, NULL);
		if (!sec->elf_data) {
			perror("elf_getdata");
			return -1;
		}

		if (sec->elf_data->d_off != 0 ||
		    sec->elf_data->d_size != sec->sh.sh_size) {
			WARN("unexpected data attributes for %s", sec->name);
			return -1;
		}

		sec->data = sec->elf_data->d_buf;
		sec->size = sec->elf_data->d_size;
	}

	/* sanity check, one more call to elf_nextscn() should return NULL */
	if (elf_nextscn(elf->elf, s)) {
		WARN("section entry mismatch");
		return -1;
	}

	return 0;
}

static int read_symbols(struct elf *elf)
{
	struct section *symtab;
	struct symbol *sym;
	int symbols_nr, i;

	symtab = find_section_by_name(elf, ".symtab");
	if (!symtab) {
		WARN("missing symbol table");
		return -1;
	}

	symbols_nr = symtab->sh.sh_size / symtab->sh.sh_entsize;

	for (i = 0; i < symbols_nr; i++) {
		sym = malloc(sizeof(*sym));
		if (!sym) {
			perror("malloc");
			return -1;
		}
		memset(sym, 0, sizeof(*sym));

		sym->idx = i;

		if (!gelf_getsym(symtab->elf_data, i, &sym->sym)) {
			perror("gelf_getsym");
			goto err;
		}

		sym->name = elf_strptr(elf->elf, symtab->sh.sh_link,
				       sym->sym.st_name);
		if (!sym->name) {
			perror("elf_strptr");
			goto err;
		}

		sym->type = GELF_ST_TYPE(sym->sym.st_info);
		sym->bind = GELF_ST_BIND(sym->sym.st_info);

		if (sym->sym.st_shndx > SHN_UNDEF &&
		    sym->sym.st_shndx < SHN_LORESERVE) {
			sym->sec = find_section_by_index(elf,
							 sym->sym.st_shndx);
			if (!sym->sec) {
				WARN("couldn't find section for symbol %s",
				     sym->name);
				goto err;
			}
			if (sym->type == STT_SECTION) {
				sym->name = sym->sec->name;
				sym->sec->sym = sym;
			}
		}

		sym->offset = sym->sym.st_value;
		sym->size = sym->sym.st_size;

		list_add_tail(&sym->list, &elf->symbols);
	}

	return 0;

err:
	free(sym);
	return -1;
}

static int read_relas(struct elf *elf)
{
	struct section *sec;
	struct rela *rela;
	int i;
	unsigned int symndx;

	list_for_each_entry(sec, &elf->sections, list) {
		if (sec->sh.sh_type != SHT_RELA)
			continue;

		sec->base = find_section_by_name(elf, sec->name + 5);
		if (!sec->base) {
			WARN("can't find base section for rela section %s",
			     sec->name);
			return -1;
		}

		sec->base->rela = sec;

		for (i = 0; i < sec->sh.sh_size / sec->sh.sh_entsize; i++) {
			rela = malloc(sizeof(*rela));
			if (!rela) {
				perror("malloc");
				return -1;
			}
			memset(rela, 0, sizeof(*rela));

			if (!gelf_getrela(sec->elf_data, i, &rela->rela)) {
				perror("gelf_getrela");
				return -1;
			}

			rela->type = GELF_R_TYPE(rela->rela.r_info);
			rela->addend = rela->rela.r_addend;
			rela->offset = rela->rela.r_offset;
			symndx = GELF_R_SYM(rela->rela.r_info);
			rela->sym = find_symbol_by_index(elf, symndx);
			if (!rela->sym) {
				WARN("can't find rela entry symbol %d for %s",
				     symndx, sec->name);
				return -1;
			}

			list_add_tail(&rela->list, &sec->relas);
		}
	}

	return 0;
}

struct section *create_rela_section(struct elf *elf, const char *name,
				    struct section *base)
{
	struct section *sec;

	sec = malloc(sizeof(*sec));
	if (!sec) {
		WARN("malloc failed");
		return NULL;
	}
	memset(sec, 0, sizeof(*sec));
	INIT_LIST_HEAD(&sec->relas);

	sec->base = base;
	sec->name = strdup(name);
	if (!sec->name) {
		WARN("strdup failed");
		return NULL;
	}
	sec->sh.sh_name = -1;
	sec->sh.sh_type = SHT_RELA;
	sec->sh.sh_entsize = sizeof(GElf_Rela);
	sec->sh.sh_addralign = 8;
	sec->sh.sh_flags = SHF_ALLOC;

	sec->elf_data = malloc(sizeof(*sec->elf_data));
	if (!sec->elf_data) {
		WARN("malloc failed");
		return NULL;
	}
	memset(sec->elf_data, 0, sizeof(*sec->elf_data));
	sec->elf_data->d_type = ELF_T_RELA;

	list_add_tail(&sec->list, &elf->sections);

	return sec;
}

static int update_shstrtab(struct elf *elf)
{
	struct section *shstrtab, *sec;
	size_t orig_size, new_size = 0, offset, len;
	char *buf;

	shstrtab = find_section_by_name(elf, ".shstrtab");
	if (!shstrtab) {
		WARN("can't find .shstrtab");
		return -1;
	}

	orig_size = new_size = shstrtab->size;

	list_for_each_entry(sec, &elf->sections, list) {
		if (sec->sh.sh_name != -1)
			continue;
		new_size += strlen(sec->name) + 1;
	}

	if (new_size == orig_size)
		return 0;

	buf = malloc(new_size);
	if (!buf) {
		WARN("malloc failed");
		return -1;
	}
	memcpy(buf, (void *)shstrtab->data, orig_size);

	offset = orig_size;
	list_for_each_entry(sec, &elf->sections, list) {
		if (sec->sh.sh_name != -1)
			continue;
		sec->sh.sh_name = offset;
		len = strlen(sec->name) + 1;
		memcpy(buf + offset, sec->name, len);
		offset += len;
	}

	shstrtab->elf_data->d_buf = shstrtab->data = buf;
	shstrtab->elf_data->d_size = shstrtab->size = new_size;
	shstrtab->sh.sh_size = new_size;

	return 0;
}

static int update_strtab(struct elf *elf)
{
	struct section *strtab;
	struct symbol *sym;
	size_t orig_size, new_size = 0, offset, len;
	char *buf;

	strtab = find_section_by_name(elf, ".strtab");
	if (!strtab) {
		WARN("can't find .strtab");
		return -1;
	}

	orig_size = new_size = strtab->size;

	list_for_each_entry(sym, &elf->symbols, list) {
		if (sym->sym.st_name != -1)
			continue;
		new_size += strlen(sym->name) + 1;
	}

	if (new_size == orig_size)
		return 0;

	buf = malloc(new_size);
	if (!buf) {
		WARN("malloc failed");
		return -1;
	}
	memcpy(buf, (void *)strtab->data, orig_size);

	offset = orig_size;
	list_for_each_entry(sym, &elf->symbols, list) {
		if (sym->sym.st_name != -1)
			continue;
		sym->sym.st_name = offset;
		len = strlen(sym->name) + 1;
		memcpy(buf + offset, sym->name, len);
		offset += len;
	}

	strtab->elf_data->d_buf = strtab->data = buf;
	strtab->elf_data->d_size = strtab->size = new_size;
	strtab->sh.sh_size = new_size;

	return 0;
}

static int update_symtab(struct elf *elf)
{
	struct section *symtab, *sec;
	struct symbol *sym;
	char *buf;
	size_t size;
	int offset = 0, nr_locals = 0, idx, nr_syms;

	idx = 0;
	list_for_each_entry(sec, &elf->sections, list)
		sec->idx = idx++;

	idx = 0;
	list_for_each_entry(sym, &elf->symbols, list) {
		sym->idx = idx++;
		if (sym->sec)
			sym->sym.st_shndx = sym->sec->idx;
	}
	nr_syms = idx;

	symtab = find_section_by_name(elf, ".symtab");
	if (!symtab) {
		WARN("can't find symtab");
		return -1;
	}

	symtab->sh.sh_link = find_section_by_name(elf, ".strtab")->idx;

	/* create new symtab buffer */
	size = nr_syms * symtab->sh.sh_entsize;
	buf = malloc(size);
	if (!buf) {
		WARN("malloc failed");
		return -1;
	}
	memset(buf, 0, size);

	offset = 0;
	list_for_each_entry(sym, &elf->symbols, list) {
		memcpy(buf + offset, &sym->sym, symtab->sh.sh_entsize);
		offset += symtab->sh.sh_entsize;

		if (sym->bind == STB_LOCAL)
			nr_locals++;
	}

	symtab->elf_data->d_buf = symtab->data = buf;
	symtab->elf_data->d_size = symtab->size = size;
	symtab->sh.sh_size = size;

	/* update symtab section header */
	symtab->sh.sh_info = nr_locals;

	return 0;
}

static int update_relas(struct elf *elf)
{
	struct section *sec, *symtab;
	struct rela *rela;
	int nr_relas, idx, size;
	GElf_Rela *relas;

	symtab = find_section_by_name(elf, ".symtab");

	list_for_each_entry(sec, &elf->sections, list) {
		if (!is_rela_section(sec))
			continue;

		sec->sh.sh_link = symtab->idx;
		if (sec->base)
			sec->sh.sh_info = sec->base->idx;

		nr_relas = 0;
		list_for_each_entry(rela, &sec->relas, list)
			nr_relas++;

		size = nr_relas * sizeof(*relas);
		relas = malloc(size);
		if (!relas) {
			WARN("malloc failed");
			return -1;
		}

		sec->elf_data->d_buf = sec->data = relas;
		sec->elf_data->d_size = sec->size = size;
		sec->sh.sh_size = size;

		idx = 0;
		list_for_each_entry(rela, &sec->relas, list) {
			relas[idx].r_offset = rela->offset;
			relas[idx].r_addend = rela->addend;
			relas[idx].r_info = GELF_R_INFO(rela->sym->idx,
							rela->type);
			idx++;
		}
	}

	return 0;
}

static int write_file(struct elf *elf, const char *file)
{
	int fd;
	Elf *e;
	GElf_Ehdr eh, ehout;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr sh;
	struct section *sec;

	fd = creat(file, 0664);
	if (fd == -1) {
		WARN("couldn't create %s", file);
		return -1;
	}

	e = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!e) {
		WARN("elf_begin failed");
		return -1;
	}

	if (!gelf_newehdr(e, gelf_getclass(elf->elf))) {
		WARN("gelf_newehdr failed");
		return -1;
	}

	if (!gelf_getehdr(e, &ehout)) {
		WARN("gelf_getehdr failed");
		return -1;
	}

	if (!gelf_getehdr(elf->elf, &eh)) {
		WARN("gelf_getehdr failed");
		return -1;
	}

	memset(&ehout, 0, sizeof(ehout));
	ehout.e_ident[EI_DATA] = eh.e_ident[EI_DATA];
	ehout.e_machine = eh.e_machine;
	ehout.e_type = eh.e_type;
	ehout.e_version = EV_CURRENT;
	ehout.e_shstrndx = find_section_by_name(elf, ".shstrtab")->idx;

	list_for_each_entry(sec, &elf->sections, list) {
		if (!sec->idx)
			continue;
		scn = elf_newscn(e);
		if (!scn) {
			WARN("elf_newscn failed");
			return -1;
		}

		data = elf_newdata(scn);
		if (!data) {
			WARN("elf_newdata failed");
			return -1;
		}

		if (!elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY)) {
			WARN("elf_flagdata failed");
			return -1;
		}

		data->d_type = sec->elf_data->d_type;
		data->d_buf = sec->elf_data->d_buf;
		data->d_size = sec->elf_data->d_size;

		if (!gelf_getshdr(scn, &sh)) {
			WARN("gelf_getshdr failed");
			return -1;
		}

		sh = sec->sh;

		if (!gelf_update_shdr(scn, &sh)) {
			WARN("gelf_update_shdr failed");
			return -1;
		}
	}

	if (!gelf_update_ehdr(e, &ehout)) {
		WARN("gelf_update_ehdr failed");
		return -1;
	}

	if (elf_update(e, ELF_C_WRITE) < 0) {
		fprintf(stderr, "%s\n", elf_errmsg(-1));
		WARN("elf_update failed");
		return -1;
	}

	return 0;
}

int elf_write_file(struct elf *elf, const char *file)
{
	int ret;

	ret = update_shstrtab(elf);
	if (ret)
		return ret;

	ret = update_strtab(elf);
	if (ret)
		return ret;

	ret = update_symtab(elf);
	if (ret)
		return ret;

	ret = update_relas(elf);
	if (ret)
		return ret;

	return write_file(elf, file);
}

struct elf *elf_open(const char *name)
{
	struct elf *elf;

	elf_version(EV_CURRENT);

	elf = malloc(sizeof(*elf));
	if (!elf) {
		perror("malloc");
		return NULL;
	}
	memset(elf, 0, sizeof(*elf));

	INIT_LIST_HEAD(&elf->sections);
	INIT_LIST_HEAD(&elf->symbols);

	elf->fd = open(name, O_RDONLY);
	if (elf->fd == -1) {
		perror("open");
		goto err;
	}

	elf->elf = elf_begin(elf->fd, ELF_C_READ_MMAP, NULL);
	if (!elf->elf) {
		perror("elf_begin");
		goto err;
	}

	if (!gelf_getehdr(elf->elf, &elf->ehdr)) {
		perror("gelf_getehdr");
		goto err;
	}

	if (read_sections(elf))
		goto err;

	if (read_symbols(elf))
		goto err;

	if (read_relas(elf))
		goto err;

	return elf;

err:
	elf_close(elf);
	return NULL;
}

void elf_close(struct elf *elf)
{
	struct section *sec, *tmpsec;
	struct symbol *sym, *tmpsym;
	struct rela *rela, *tmprela;

	list_for_each_entry_safe(sym, tmpsym, &elf->symbols, list) {
		list_del(&sym->list);
		free(sym);
	}
	list_for_each_entry_safe(sec, tmpsec, &elf->sections, list) {
		list_for_each_entry_safe(rela, tmprela, &sec->relas, list) {
			list_del(&rela->list);
			free(rela);
		}
		list_del(&sec->list);
		free(sec);
	}
	if (elf->fd > 0)
		close(elf->fd);
	if (elf->elf)
		elf_end(elf->elf);
	free(elf);
}
