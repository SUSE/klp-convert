/*
 * Copyright (C) 2016 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2017 Joao Moreira   <jmoreira@suse.de>
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "elf.h"
#include "list.h"
#include "klp-convert.h"
#ifndef LOCAL_KLP_DEFS
#include <linux/livepatch.h>
#endif

/*
 * Symbols parsed from Symbols.list are kept in two lists:
 * - symbols: keeps non-exported symbols
 * - exp_symbols: keeps exported symbols (__ksymtab_prefixed)
 */
static LIST_HEAD(symbols);
static LIST_HEAD(exp_symbols);

/* In-livepatch user-provided symbol positions are kept in list usr_symbols */
static LIST_HEAD(usr_symbols);

static void free_syms_lists(void)
{
	struct symbol_entry *entry, *aux;
	struct sympos *sp, *sp_aux;

	list_for_each_entry_safe(entry, aux, &symbols, list) {
		free(entry->object_name);
		free(entry->symbol_name);
		list_del(&entry->list);
		free(entry);
	}

	list_for_each_entry_safe(entry, aux, &exp_symbols, list) {
		free(entry->object_name);
		free(entry->symbol_name);
		list_del(&entry->list);
		free(entry);
	}

	list_for_each_entry_safe(sp, sp_aux, &usr_symbols, list) {
		free(sp->object_name);
		free(sp->symbol_name);
		list_del(&sp->list);
		free(sp);
	}
}

/* Parses file and fill symbols and exp_symbols list */
static bool load_syms_lists(const char *symbols_list)
{
	FILE *fsyms;
	struct symbol_entry *entry;
	size_t len = 0;
	ssize_t n;
	char *obj = NULL, *sym = NULL;

	fsyms = fopen(symbols_list, "r");
	if (!fsyms) {
		WARN("Unable to open Symbol list: %s", symbols_list);
		return false;
	}

        /* read file format version */
	n = getline(&sym, &len, fsyms);
        if (n <= 0) {
		WARN("Unable to read Symbol list: %s", symbols_list);
		return false;
	}

	if (strncmp(sym, "klp-convert-symbol-data.0.1", 27) != 0) {
		WARN("Symbol list is in unknown format.");
		return false;
	}

	len = 0;
	sym = NULL;

	/* read file */
	n = getline(&sym, &len, fsyms);
	while (n > 0) {
		if (sym[n-1] == '\n')
			sym[n-1] = '\0';

		/* Objects in Symbols.list are flagged with '*' */
		if (sym[0] == '*') {
			if (obj)
				free(obj);
			obj = strdup(sym+1);
			if (!obj) {
				WARN("Unable to allocate object name\n");
				return false;
			}
			free(sym);
		} else {
			entry = calloc(1, sizeof(struct symbol_entry));
			if (!entry) {
				WARN("Unable to allocate Symbol entry\n");
				return false;
			}

			entry->object_name = strdup(obj);
			if (!entry->object_name) {
				WARN("Unable to allocate entry object name\n");
				return false;
			}

			entry->symbol_name = sym;

			if (strncmp(entry->symbol_name, "__ksymtab_", 10) == 0)
				list_add(&entry->list, &exp_symbols);
			else
				list_add(&entry->list, &symbols);
		}
		len = 0;
		sym = NULL;
		n = getline(&sym, &len, fsyms);
	}
	free(sym);
	free(obj);
	fclose(fsyms);
	return true;
}

/* Searches for sympos of specific symbol in usr_symbols list */
static bool get_usr_sympos(struct symbol *s, struct sympos *sp)
{
	struct sympos *aux;

	list_for_each_entry(aux, &usr_symbols, list) {
		if (strcmp(aux->symbol_name, s->name) == 0) {
			sp->symbol_name = aux->symbol_name;
			sp->object_name = aux->object_name;
			sp->pos = aux->pos;
			return true;
		}
	}
	return false;
}

/* Removes symbols used for sympos annotation from livepatch elf object */
static void clear_sympos_symbols(struct section *sec, struct elf *klp_elf)
{
	struct symbol *sym, *aux;

	list_for_each_entry_safe(sym, aux, &klp_elf->symbols, list) {
		if (sym->sec == sec) {
			list_del(&sym->list);
			free(sym);
		}
	}
}

/* Removes annotation from livepatch elf object */
static void clear_sympos_annontations(struct elf *klp_elf)
{
	struct section *sec, *aux;

	list_for_each_entry_safe(sec, aux, &klp_elf->sections, list) {
		if (strncmp(sec->name, ".klp.module_relocs.", 19) == 0) {
			clear_sympos_symbols(sec, klp_elf);
			list_del(&sec->list);
			free(sec);
			continue;
		}
		if (strncmp(sec->name, ".rela.klp.module_relocs.", 24) == 0) {
			list_del(&sec->list);
			free(sec);
			continue;
		}
	}
}

/* Checks if two or more elements in usr_symbols have the same name */
static bool sympos_sanity_check(void)
{
	bool sane = true;
	struct sympos *sp, *aux;

	list_for_each_entry(sp, &usr_symbols, list) {
		aux = list_next_entry(sp, list);
		list_for_each_entry_from(aux, &usr_symbols, list) {
			if (strcmp(sp->symbol_name, aux->symbol_name) == 0) {
				WARN("Conflicting KLP_SYMPOS definition: \
						%s.%s,%d vs. %s.%s,%d.",
				sp->object_name, sp->symbol_name, sp->pos,
				aux->object_name, aux->symbol_name, aux->pos);
				sane = false;
			}
		}
	}
	return sane;
}

/* Parses the livepatch elf object and fills usr_symbols */
static bool load_usr_symbols(struct elf *klp_elf)
{
	char objname[MODULE_NAME_LEN];
	struct sympos *sp;
	struct section *sec, *aux, *relasec;
	struct rela *rela;
	struct klp_module_reloc *reloc;
	int i, nr_entries;

	list_for_each_entry_safe(sec, aux, &klp_elf->sections, list) {
		if (sscanf(sec->name, ".klp.module_relocs.%55s", objname) != 1)
			continue;

		relasec = sec->rela;
		reloc = sec->data;
		i = 0;
		nr_entries = sec->size / sizeof(*reloc);
		list_for_each_entry(rela, &relasec->relas, list) {
			if (i >= nr_entries) {
				WARN("section %s length beyond nr_entries\n",
						relasec->name);
				return false;
			}
			sp = calloc(1, sizeof(struct sympos));
			if (!sp) {
				WARN("Unable to allocate sympos memory\n");
				return false;
			}
			sp->object_name = strdup(objname);
			if (!sp->object_name) {
				WARN("Unable to allocate object name\n");
				return false;
			}
			sp->symbol_name = strdup(rela->sym->name);
			sp->pos = reloc[i].sympos;
			list_add(&sp->list, &usr_symbols);
			i++;
		}
		if (i != nr_entries) {
			WARN("nr_entries mismatch (%d != %d) for %s\n",
					i, nr_entries, relasec->name);
			return false;
		}
	}
	clear_sympos_annontations(klp_elf);
	return sympos_sanity_check();
}

/* prints list of valid sympos for symbol with provided name */
static void print_valid_module_relocs(char *name)
{
	struct symbol_entry *e;
	char *cur_obj = "";
	int counter;
	bool first = true;

	/* Symbols from the same object are locally gathered in the list */
	fprintf(stderr, "Valid KLP_SYMPOS for symbol %s:\n", name);
	fprintf(stderr, "-------------------------------------------------\n");
	list_for_each_entry(e, &symbols, list) {
		if (strcmp(e->object_name, cur_obj) != 0) {
			cur_obj = e->object_name;
			counter = 0;
		}
		if (strcmp(e->symbol_name, name) == 0) {
			if (counter == 0) {
				if (!first)
					fprintf(stderr, "}\n");

				fprintf(stderr, "KLP_MODULE_RELOC(%s){\n",
						cur_obj);
				first = false;
			}
			fprintf(stderr, "\tKLP_SYMPOS(%s,%d)\n", name, counter);
			counter++;
		}
	}
	fprintf(stderr, "-------------------------------------------------\n");
}

/* Searches for symbol in symbols list and returns its sympos if it is unique,
 * otherwise prints a list with all considered valid sympos
 */
static struct symbol_entry *find_sym_entry_by_name(char *name)
{
	struct symbol_entry *found = NULL;
	struct symbol_entry *e;

	list_for_each_entry(e, &symbols, list) {
		if (strcmp(e->symbol_name, name) == 0) {

			/* If there exist multiple symbols with the same
			 * name then user-provided sympos is required
			 */
			if (found) {
				WARN("Define KLP_SYMPOS for the symbol: %s",
						e->symbol_name);

				print_valid_module_relocs(name);
				return NULL;
			}
			found = e;
		}
	}
	if (found)
		return found;

	return NULL;
}

/* Checks if sympos is valid, otherwise prints valid sympos list */
static bool valid_sympos(struct sympos *sp)
{
	struct symbol_entry *e;
	int counter = 0;

	list_for_each_entry(e, &symbols, list) {
		if ((strcmp(e->symbol_name, sp->symbol_name) == 0) &&
		    (strcmp(e->object_name, sp->object_name) == 0)) {
			if (counter == sp->pos)
				return true;
			counter++;
		}
	}

	WARN("Provided KLP_SYMPOS does not match a symbol: %s.%s,%d",
			sp->object_name, sp->symbol_name, sp->pos);
	print_valid_module_relocs(sp->symbol_name);

	return false;
}

/* Returns the right sympos respective to a symbol to be relocated */
static bool find_missing_position(struct symbol *s, struct sympos *sp)
{
	struct symbol_entry *entry;

	if (get_usr_sympos(s, sp)) {
		if (valid_sympos(sp))
			return true;
		return false;
	}

	/* if no user-provided sympos, search symbol in symbols list */
	entry = find_sym_entry_by_name(s->name);
	if (entry) {
		sp->symbol_name = entry->symbol_name;
		sp->object_name = entry->object_name;
		sp->pos = 0;
		return true;
	}
	return false;
}

/* Finds or creates a klp rela section based on another given section (@oldsec)
 * and sympos (@*sp), then returns it
 */
static struct section *get_or_create_klp_rela_section(struct section *oldsec,
		struct sympos *sp, struct elf *klp_elf)
{
	char *name;
	struct section *sec;
	unsigned int length;

	length = strlen(KLP_RELA_PREFIX) + strlen(sp->object_name)
		 + strlen(oldsec->base->name) + 2;

	name = calloc(1, length);
	if (!name) {
		WARN("Memory allocation failed (%s%s.%s)\n", KLP_RELA_PREFIX,
				sp->object_name, oldsec->base->name);
		return NULL;
	}

	if (snprintf(name, length, KLP_RELA_PREFIX "%s.%s", sp->object_name,
				oldsec->base->name) >= length) {
		WARN("Length error (%s)", name);
		free(name);
		return NULL;
	}

	sec = find_section_by_name(klp_elf, name);
	if (!sec)
		sec = create_rela_section(klp_elf, name, oldsec->base);

	if (sec)
		sec->sh.sh_flags |= SHF_RELA_LIVEPATCH;

	free(name);
	return sec;
}

/* Converts rela symbol names */
static bool convert_klp_symbol(struct symbol *s, struct sympos *sp)
{
	char *name;
	char pos[4];	/* assume that pos will never be > 999 */
	unsigned int length;

	if (snprintf(pos, sizeof(pos), "%d", sp->pos) > sizeof(pos)) {
		WARN("Insuficient buffer for expanding sympos (%s.%s,%d)\n",
				sp->object_name, sp->symbol_name, sp->pos);
		return false;
	}

	length = strlen(KLP_SYM_PREFIX) + strlen(sp->object_name)
		 + strlen(sp->symbol_name) + 3;

	name = calloc(1, length);
	if (!name) {
		WARN("Memory allocation failed (%s%s.%s,%s)\n", KLP_SYM_PREFIX,
				sp->object_name, sp->symbol_name, pos);
		return false;
	}

	if (snprintf(name, length, KLP_SYM_PREFIX "%s.%s,%s", sp->object_name,
				sp->symbol_name, pos) >= length) {

		WARN("Length error (%s%s.%s,%s)", KLP_SYM_PREFIX,
				sp->object_name, sp->symbol_name, pos);

		return false;
	}

	s->name = name;
	s->sec = NULL;
	s->sym.st_name = -1;
	s->sym.st_shndx = SHN_LIVEPATCH;

	return true;
}

/* Convert rela that cannot be resolved by the clasic module loader
 * to the special klp rela one.
 */
static bool convert_rela(struct section *oldsec, struct rela *r,
		struct sympos *sp, struct elf *klp_elf)
{
	struct section *sec;
	struct rela *r1, *r2;

	sec = get_or_create_klp_rela_section(oldsec, sp, klp_elf);
	if (!sec) {
		WARN("Can't create or access klp.rela section (%s.%s)\n",
				sp->object_name, sp->symbol_name);
		return false;
	}

	if (!convert_klp_symbol(r->sym, sp)) {
		WARN("Unable to convert symbol name (%s.%s)\n", sec->name,
				r->sym->name);
		return false;
	}

	/* Move the converted rela to klp rela section */
	list_for_each_entry_safe(r1, r2, &oldsec->relas, list) {
		if(r1->sym->name == r->sym->name) {
			list_del(&r1->list);
			list_add(&r1->list, &sec->relas);
		}
	}
	return true;
}

/* Checks if given symbol name matches a symbol in exp_symbols */
static bool is_exported(char *sname)
{
	struct symbol_entry *e;

	/* exp_symbols itens are prefixed with __ksymtab_ - comparisons must
	 * skip prefix and check if both are properly null-terminated
	 */
	list_for_each_entry(e, &exp_symbols, list) {
		if (strcmp(e->symbol_name + 10, sname) == 0)
			return true;
	}
	return false;
}

/* Checks if a symbol was previously klp-converted based on its name */
static bool is_converted(char *sname)
{
	int len = strlen(KLP_SYM_PREFIX);

	if (strncmp(sname, KLP_SYM_PREFIX, len) == 0)
		return true;
	return false;
}

/* Checks if symbol must be converted (conditions):
 * not resolved, not already converted or isn't an exported symbol
 */
static bool must_convert(struct symbol *sym)
{
	/* already resolved? */
	if (sym->sec)
		return false;

	return (!(is_converted(sym->name) || is_exported(sym->name)));
}

int main(int argc, const char **argv)
{
	const char *klp_in_module, *klp_out_module, *symbols_list;
	struct rela *rela, *tmprela;
	struct section *sec, *aux;
	struct sympos sp;
	struct elf *klp_elf;

	if (argc != 4) {
		WARN("Usage: %s <Symbols.list> <input.ko> <out.ko>", argv[0]);
		return -1;
	}

	symbols_list = argv[1];
	klp_in_module = argv[2];
	klp_out_module = argv[3];

	klp_elf = elf_open(klp_in_module);
	if (!klp_elf) {
		WARN("Unable to read elf file %s\n", klp_in_module);
		return -1;
	}

	if (!load_syms_lists(symbols_list))
		return -1;

	if (!load_usr_symbols(klp_elf)) {
		WARN("Unable to load user-provided sympos");
		return -1;
	}

	list_for_each_entry_safe(sec, aux, &klp_elf->sections, list) {
		if (!is_rela_section(sec))
			continue;

		list_for_each_entry_safe(rela, tmprela, &sec->relas, list) {
			if (!must_convert(rela->sym))
				continue;

			if (!find_missing_position(rela->sym, &sp)) {
				WARN("Unable to find missing symbol");
				return -1;
			}
			if (!convert_rela(sec, rela, &sp, klp_elf)) {
				WARN("Unable to convert relocation");
				return -1;
			}
		}
	}

	free_syms_lists();
	if (elf_write_file(klp_elf, klp_out_module))
		return -1;

	return 0;
}

/* Functions kept commented since they might be useful for future debugging */

/* Dumps sympos list (useful for debugging purposes)
 * static void dump_sympos(void)
 * {
 *	struct sympos *sp;
 *
 *	fprintf(stderr, "BEGIN OF SYMPOS DUMP\n");
 *	list_for_each_entry(sp, &usr_symbols, list) {
 *		fprintf(stderr, "%s %s %d\n", sp->symbol_name, sp->object_name,
 *				sp->pos);
 *	}
 *	fprintf(stderr, "END OF SYMPOS DUMP\n");
 * }
 *
 *
 * / Dump symbols list for debugging purposes /
 * static void dump_symbols(void)
 * {
 *	struct symbol_entry *entry;
 *
 *	fprintf(stderr, "BEGIN OF SYMBOLS DUMP\n");
 *	list_for_each_entry(entry, &symbols, list)
 *		printf("%s %s\n", entry->object_name, entry->symbol_name);
 *	fprintf(stderr, "END OF SYMBOLS DUMP\n");
 * }
 */
