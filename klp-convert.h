#define KLP_RELA_PREFIX	".klp.rela."
#define KLP_SYM_PREFIX	".klp.sym."

struct klp_module_reloc {
	void *sym;
	unsigned int sympos;
} __attribute__((packed));
