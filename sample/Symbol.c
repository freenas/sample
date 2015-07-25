#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>

#include "Symbol.h"
#include "SymbolGroup.h"


typedef struct SymbolPoolInternal {
	size_t count;	// Number of elements
	int	sorted;	// Don't sort until we want to do a search
	SymbolFile_t	*files;
} SymbolPoolInternal_t;

void
DumpSymbolPool(SymbolPool_t *pool)
{
	SymbolPoolInternal_t *p = (void*)pool;
	size_t indx;

	for (indx = 0; indx < p->count; indx++) {
		DumpSymbolGroup(p->files[indx].group);
	}
}

SymbolFile_t *
CreateSymbolFile(const char *path, off_t offset, void *addr, size_t len)
{
	SymbolFile_t *retval = NULL;
	const char *copy = strdup(path);

	if (copy) {
		retval = calloc(1, sizeof(*retval));
		if (retval) {
			retval->pathname = copy;
			retval->offset = offset;
			retval->base = (uintptr_t)addr;
			retval->len = len;
			retval->group = CreateSymbolGroup(copy);
		} else {
			free((void*)copy);
			errno = ENOMEM;
		}
	}
	return retval;
}

void
ReleaseSymbolFile(SymbolFile_t *s)
{
	if (s) {
		if (s->pathname)
			free((void*)s->pathname);
		if (s->group)
			ReleaseSymbolGroup(s->group);
		free((void*)s);
	}
	return;
}

void
SymbolFileSetReloc(SymbolFile_t *sf)
{
	sf->force_reloc = 1;
}

SymbolPool_t
CreateSymbolPool(void)
{
	SymbolPoolInternal_t *retval = NULL;

	retval = calloc(1, sizeof(*retval));
done:
	return (SymbolPool_t)retval;
}

void
ReleaseSymbolPool(SymbolPool_t p_in)
{
	SymbolPoolInternal_t *p = (SymbolPoolInternal_t*)p_in;
	if (p) {
		size_t indx;

		for (indx = 0; indx < p->count; indx++) {
			if (p->files[indx].pathname)
				free((void*)p->files[indx].pathname);
		}
		free(p);
	}
}

int
AddSymbolFile(SymbolPool_t p_in, SymbolFile_t *f)
{
	SymbolPoolInternal_t *p = (SymbolPool_t)p_in;
	SymbolFile_t *tmp;
	const char *copy = strdup(f->pathname);

	if (copy == NULL) {
		return ENOMEM;
	}

	tmp = realloc(p->files, sizeof(*tmp) * (p->count + 1));
	if (tmp == NULL) {
		free((void*)copy);
		return ENOMEM;
	}
	p->files = tmp;
	// And now we re-use tmp
	tmp = &p->files[p->count++];
	*tmp = *f;
	tmp->pathname = copy;
	if (f->group) {
		// Need to copy the symbol group.  Would be easier if we used reference counts
		tmp->group = CopySymbolGroup(f->group);
	}
	p->sorted = 0;
	return 0;
}

/*
 * Add the elements of small_in to big_in.
 */
int
AddSymbolPool(SymbolPool_t big_in, SymbolPool_t small_in)
{
	SymbolPoolInternal_t *big = big_in, *small = small_in;
	SymbolFile_t *tmp;
	size_t indx;

	tmp = realloc(big->files, sizeof(*tmp) * (big->count + small->count));
	if (tmp == NULL) {
		return ENOMEM;
	}
	big->files = tmp;

	for (indx = 0; indx < small->count; indx++) {
		const char *copy = strdup(small->files[indx].pathname);
		if (copy == NULL) {
			size_t bail;
			for (bail = 0; bail < indx; bail++) {
				free((void*)big->files[big->count + bail].pathname);
			}
			return ENOMEM;
		}
		big->files[big->count + indx] = small->files[indx];
		big->files[big->count + indx].pathname = copy;
	}
	big->count += small->count;
	big->sorted = 0;

	return 0;
}

static int
CompareSymbolFiles(const void *l_in, const void *r_in)
{
	const SymbolFile_t *left = l_in, *right = r_in;

	if (left->base < right->base)
		return -1;
	if (left->base > right->base)
		return 1;
	return 0;
}

static void
SortPool(SymbolPoolInternal_t *pool)
{
	qsort(pool->files, pool->count, sizeof(SymbolFile_t), CompareSymbolFiles);
	pool->sorted = 1;
}

/*
 * Given an address, find the SymbolPool for it.  Return an offset into the
 * file.
 */
SymbolFile_t *
FindSymbolFileByAddress(SymbolPool_t pool_in, void *addr, off_t *offptr)
{
	SymbolPoolInternal_t *pool = pool_in;
	SymbolFile_t *retval = NULL;
	size_t indx;
	off_t map_offset;

	if (pool->sorted == 0) {
		SortPool(pool);
	}

	for (indx = 0; indx < pool->count; indx++) {
		uintptr_t base = (uintptr_t)pool->files[indx].base;
		uintptr_t end = base + pool->files[indx].len;
//		fprintf(stderr, "%s(addr = %p):  base = %#llx, end = %#llx\n", __FUNCTION__, addr, (long long)base, (long long)end);
		if (base <= (uintptr_t)addr &&
		    end > (uintptr_t)addr) {
			// We have a match!
			retval = &pool->files[indx];
			map_offset = (uintptr_t)addr - base;
			if (offptr)
				*offptr = map_offset;
			return retval;
		}
	}
	return retval;
}

/*
 * Similar to the above, except that it will try to narrow it down to
 * the closest symbol.  If it can't find a symbol for it, it'll return
 * the filename, just as with FindSymblFileForAddress would.
 *
 * The value returned will be NULL if it could not be found, or a allocated
 * copy of the name (file name, or filename:symbolname).  The caller is
 * responsible for calling free() on this.
 */

char *
FindSymbolForAddress(SymbolPool_t pool_in, void *addr, off_t *offPtr)
{
	SymbolPoolInternal_t *pool = pool_in;
	SymbolFile_t *sf = NULL;
	off_t offset;
	char *retval = NULL;

	sf = FindSymbolFileByAddress(pool_in, addr, &offset);
	if (sf == NULL) {
		return NULL;
	}

	if (sf->group == NULL) {
		retval = strdup(sf->pathname);
	} else {
		struct SymbolGroup *group = sf->group;
		struct Symbol *symbol;
		symbol = FindSymbolInGroup(group, (uintptr_t)addr, sf->base);
		if (symbol == NULL) {
			retval = strdup(sf->pathname);
		} else {
			/*
			 * If we found a symbol, then the offset is either addr - symbol->address,
			 * or (addr - sf->base) - symbol->address, if symbol->reloc is true.  However,
			 * for files that don't have symbols set up in a way that makes sense, doing
			 * this can have the offset be beyond the range of the mapping.  So in
			 * that case, we need to just use the filename.
			 */
			offset = ((uintptr_t)addr - ((symbol->reloc || sf->force_reloc) ? sf->base : 0)) - symbol->address;
			if ((sf->base + offset) < sf->base ||
			    (sf->base + offset) > (sf->base + sf->len)) {
				// The math here is just wrong.
				// We haven't found the symbol, so we shouldn't pretend we have.
				return NULL;
			} else {
				asprintf(&retval, "%s:%s", sf->pathname, symbol->name);
			}
		}
	}
	if (retval && offPtr)
		*offPtr = offset;
	return retval;
}

void
IterateSymbolPool(SymbolPool_t pool_in, int (^handler)(SymbolFile_t *))
{
	SymbolPoolInternal_t *pool = pool_in;
	size_t counter;

	if (pool->sorted == 0) {
		SortPool(pool);
	}

	for (counter = 0; counter < pool->count; counter++) {
		if (handler(&pool->files[counter]) == 0) {
			break;
		}
	}
	return;
}
