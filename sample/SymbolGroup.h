#ifndef SYMBOLGROUP_H
# define SYMBOLGROUP_H

/*
 * The following data structures are used to maintain
 * symbols.
 */

struct Symbol {
	uintptr_t	address;
	int		reloc;	// Whether or not the symbol is relocatable
	char		name[0];
};

struct SymbolGroup {
	char		*name;	// Name of the group (typically the filename)
	size_t		references;	// Number of copies of this group
	size_t		alloced;	// How many allocated
	size_t		count;		// How many are actually used
	int		sorted;	// Whether it's sorted or not
	struct Symbol	**symbols;	// An array of pointers
};

struct SymbolGroup *CreateSymbolGroup(const char *fname);
struct SymbolGroup *CopySymbolGroup(struct SymbolGroup *);
void SortSymbolGroup(struct SymbolGroup *);
struct Symbol *FindSymbolInGroup(struct SymbolGroup *, uintptr_t addr, uintptr_t base);
void AddSymbolToGroup(struct SymbolGroup *, const char *, uintptr_t, int);
void ReleaseSymbolGroup(struct SymbolGroup *);

#endif
