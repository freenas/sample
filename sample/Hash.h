#ifndef HASH_H
# define HASH_H

typedef void *hash_t;	// visible type

/*
 * Create a hash.  We need to know the size of the elements,
 * and how to get a key from it.  (The key is a numeric value used
 * to determine which bucket.)  The get_key block returns that value;
 * the comapre block compares two elements, and returns 1 if they are
 * equal, and 0 if they are not equal.  release is called when the
 * hash is destroyed, to release.  If it's NULL, nothing is done.
 */
hash_t CreateHash(size_t elem_size,
		  size_t (^get_key)(void*),
		  int (^compare)(void *, void *),
		  void (^release)(void*));

/*
 * Search the hash for the given object.  Only the key (see above) is checked.
 * Returns NULL if it is not found.
 */
void *SearchHash(hash_t hashIn, void *object);

/*
 * Add an element to the hash.
 */
void AddHashElement(hash_t hashIn, void *object);

/*
 * Destroy a cache.  This also free's up all of the memory
 * allocated.
 */
void DestroyHash(hash_t hashIn);

/*
 * Count the number of entries in the hash.
 */
size_t HashEntriesCount(hash_t hashIn);

/*
 * Iterate over all the entries in a hash;
 * If the block returns 0, it stops.
 */
void IterateHash(hash_t hashIn, int (^handler)(void *object));

#endif /* HASH_H */
