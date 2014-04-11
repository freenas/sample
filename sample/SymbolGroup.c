#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>

#include <libutil.h>
#include <bfd.h>

#include "Symbol.h"
#include "SymbolGroup.h"

enum { false = 0, true = 1 };

void
DumpSymbolGroup(struct SymbolGroup *group)
{
	if (group == NULL) {
		printf("<null>\n");
		return;
	} else {
		int indx;
		if (group->name) {
			printf("Group %s: ", group->name);
		} else {
			printf("Unknown group: ");
		}
		printf("{\n\talloced:\t%zu\n\tcount:\t%zu\n\tsorted:%d\n\t{\n",
		       group->alloced, group->count, group->sorted);
		for (indx = 0; indx < group->count; indx++) {
			struct Symbol *ptr = group->symbols[indx];
			printf("\t\t{ addr %p, %s, `%s'}\n",
			       (void*)ptr->address,
			       ptr->reloc ? "relocatable" : "absolute",
			       ptr->name);
		}
		printf("\t}\n");
	}
	return;
}

void
ReleaseSymbolGroup(struct SymbolGroup *group)
{
	if (group) {
		size_t indx;
		if (--group->references != 0) {
			return;
		}
		for (indx = 0; indx < group->count; indx++) {
			free(group->symbols[indx]);
		}
	        if (group->name) free(group->name);
		free(group->symbols);
		free(group);
	}
	return;
}


void
AddSymbolToGroup(struct SymbolGroup *group,
		 const char *name,
		 uintptr_t addr,
		 int reloc)
{
	struct Symbol *sym = NULL;

	if (group == NULL) {
		return;
	}
	if ((group->count + 1) > group->alloced) {
		struct Symbol **tmp = realloc(group->symbols, (group->alloced + 10) * sizeof(*group));
		if (tmp == NULL) {
			warn("Cannot allocate %zu symbol structures", group->alloced + 10);
			return;
		}
		group->alloced += 10;
		group->symbols = tmp;
	}
	sym = calloc(1, sizeof(*sym) + strlen(name) + 1);
	if (sym == NULL) {
		warn("Could not allocate %zu bytes for new symbol `%s'", sizeof(*sym) + strlen(name) + 1, name);
	} else {
		sym->address = addr;
		sym->reloc = reloc;
		strcpy(sym->name, name);
		group->symbols[group->count++] = sym;
		group->sorted = 0;
#ifdef DEBUG_SYMBOLS
		fprintf(stderr, "Added { %p, %d, %s }\n", (void*)sym->address, sym->reloc, sym->name);
#endif
	}
	return;
}

static int
CompareSymbols(const void *l, const void *r)
{
	const struct Symbol * const *left = l, * const *right = r;
	int retval;

	if ((*left)->address < (*right)->address)
		retval = -1;
	else if ((*left)->address > (*right)->address)
		retval = 1;
	else
		retval = strcmp((*left)->name, (*right)->name);
//	fprintf(stderr, "left = { %p, %s }, right = { %p, %s }: %d\n", (void*)left->address, left->name, (void*)right->address, right->name, retval);

	return retval;
}

void
SortSymbolGroup(struct SymbolGroup *group)
{
	if (group->sorted == 0) {
		qsort(group->symbols, group->count, sizeof(struct Symbol*), CompareSymbols);
		group->sorted = 1;
	}
	return;
}

/*
 * Find the first address that is less than the given one,
 * but not greater than.
 */
struct Symbol *
FindSymbolInGroup(struct SymbolGroup *group, uintptr_t addr, uintptr_t base)
{
	size_t indx;
	struct Symbol *retval = NULL;

#ifdef DEBUG_SYMBOLS
	fprintf(stdout, "%s(%p {%s}, %p, %p)\n", __FUNCTION__, group, (group && group->name) ? group->name : "<unknown>", (void*)addr, (void*)base);
#endif

	if (group == NULL ||
	    group->count == 0)
		return NULL;

	SortSymbolGroup(group);

	for (indx = 0;
	     indx < group->count;
	     indx++) {
		struct Symbol *ptr = group->symbols[indx];
#ifdef DEBUG_SYMBOLS
		fprintf(stdout, "%s:  addr = %p, current symbol = { %p, %d, %s }\n", __FUNCTION__, (void*)addr, (void*)ptr->address, ptr->reloc, ptr->name);
#endif
		if (addr > (ptr->address + (ptr->reloc ? base : 0))) {
			retval = ptr;
		}
	}

	return retval;
}

static struct SymbolGroup *
AllocSymbolGroup(const char *name, size_t howmany)
{
	struct SymbolGroup *retval = NULL;

	retval = calloc(1, sizeof(struct SymbolGroup));
	if (retval) {
		retval->references = 1;
		retval->name = name ? strdup(name) : NULL;
		retval->symbols = calloc(howmany ? howmany : 10, sizeof(struct Symbol*));
		if (retval->symbols) {
			retval->count = 0;
			retval->alloced = howmany;
		}
	}
	return retval;
}

static struct SymbolGroup *
slurp_symtab(bfd *abfd)
{
	long symcount;
	unsigned int size;
	struct SymbolGroup *retval = NULL;
	asymbol **syms;
	int dynamic = false;

	if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0 ||
	    (symcount = bfd_read_minisymbols(abfd, dynamic, (PTR) & syms, &size)) == 0) {
		dynamic = true;
		symcount = bfd_read_minisymbols(abfd, dynamic /* dynamic */ ,
						(PTR) & syms, &size);
	}

	if (symcount > 0) {
		uint8_t *symtab = (uint8_t*)syms;
		size_t sym_index;

		retval = AllocSymbolGroup(abfd->filename, symcount);

		for (sym_index = 0; sym_index < symcount; sym_index++) {
			asymbol *full_sym = bfd_make_empty_symbol(abfd);
			void *sym = (void*)(symtab + (size * sym_index));
			if (full_sym) {
				full_sym = bfd_minisymbol_to_symbol(abfd, dynamic, sym, full_sym);
				if (full_sym->name) {
#ifdef DEBUG_SYMBOLS
					fprintf(stderr, "%s %#lx %#lx section %s flags %#x\n", full_sym->name, bfd_asymbol_base(full_sym), full_sym->value, full_sym->section->name, full_sym->flags);
#endif

					if ((full_sym->flags & ( BSF_SECTION_SYM | BSF_DEBUGGING | BSF_CONSTRUCTOR | BSF_WARNING | BSF_INDIRECT | BSF_FILE | BSF_DEBUGGING_RELOC | BSF_RELC | BSF_SRELC | BSF_SYNTHETIC)) == 0 &&
					    bfd_asymbol_value(full_sym) != 0)
						AddSymbolToGroup(retval, full_sym->name,
								 bfd_asymbol_value(full_sym),
								 full_sym->flags & BSF_DYNAMIC);
#ifdef DEBUG_SYMBOLS
					fprintf(stderr, "%s %#lx %#lx section %s, symbol is%s relocatable\n", full_sym->name, bfd_asymbol_base(full_sym), full_sym->value, full_sym->section->name, full_sym->flags & BSF_DYNAMIC ? "" : " not");
#endif
				}
			}
		}
	}

	return retval;
}

static void
no_bfd_error(const char *fmt, ...)
{
	return;
}


struct SymbolGroup *
CopySymbolGroup(struct SymbolGroup *orig)
{
	orig->references++;
	return orig;
}

struct SymbolGroup *
CreateSymbolGroup(const char *fname)
{
	bfd *abfd;
	struct SymbolGroup *retval = NULL;

#ifdef DEBUG_SYMBOLS
	fprintf(stderr, "%s(%s)\n", __FUNCTION__, fname);
#endif
	abfd = bfd_openr(fname, NULL);
	if (abfd) {
		if (bfd_check_format(abfd, bfd_object) != 0) {
			retval = slurp_symtab(abfd);
		}
		bfd_close(abfd);
	}
	return retval;
}
