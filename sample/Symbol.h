#ifndef SYMBOL_H
# define SYMBOL_H

/*
 * Data types and functions for maintaining and finding
 * symbols.
 */

struct SymbolGroup;	// A group of symbols
typedef struct SymbolFile {
	const char *pathname;
	off_t offset;	// Offset of file that is mapped into memory
	uintptr_t	base;	// Where it's mapped to in memory
	size_t len;	// How much of it is mapped to in memory
	int	force_reloc;	// Treat the symbols in it as actually relocatable
	struct SymbolGroup *group;	// Symbols for this object.
} SymbolFile_t;

SymbolFile_t *CreateSymbolFile(const char *path, off_t offset, void *addr, size_t len);
void ReleaseSymbolFile(SymbolFile_t *);

void SymbolFileSetReloc(SymbolFile_t *);

typedef void *SymbolPool_t;	// Actually an array of SymbolFile_t

SymbolPool_t CreateSymbolPool(void);
void ReleaseSymbolPool(SymbolPool_t);

// These two return 0 on success, errno on failure
int AddSymbolFile(SymbolPool_t, SymbolFile_t *);
int AddSymbolPool(SymbolPool_t big, SymbolPool_t small);	// Add the contents of small to big

/*
 * This one requires a bit of explanation:
 * Given an address, say 0x123480, find the corresponding
 * SymbolFile for it.  If kernel were loaded at 0xff800000 <size 1M>, and
 * libc.so were loaded at 0x120000 <size 1m>, and /bin/sh were loaded at
 * 0x1000 <size 1m>, then we would want libc.so, and an offset of 0x3480.
 * (Also have to take into account the offset of the file that is mapped
 * in, and so forth.  Too bad we don't get the offset information.)
 *
 * If optr is NULL, it doesn't return the offset into the SymbolFile_t.
 */
SymbolFile_t *FindSymbolFileByAddress(SymbolPool_t pool, void *addr, off_t *optr);
char *FindSymbolForAddress(SymbolPool_t pool, void *addr, off_t *optr);

void IterateSymbolPool(SymbolPool_t pool, int (^)(SymbolFile_t *));
#endif /* SYMBOL_H */
