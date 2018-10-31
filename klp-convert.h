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

#define SHN_LIVEPATCH		0xff20
#define SHF_RELA_LIVEPATCH	0x00100000
#define MODULE_NAME_LEN		(64 - sizeof(GElf_Addr))
#define WARN(format, ...) \
	fprintf(stderr, "klp-convert: " format "\n", ##__VA_ARGS__)

struct symbol_entry {
	struct list_head list;
	char *symbol_name;
	char *object_name;
};

struct sympos {
	struct list_head list;
	char *symbol_name;
	char *object_name;
	int pos;
};

struct klp_module_reloc {
	void *sym;
	unsigned int sympos;
} __attribute__((packed));
