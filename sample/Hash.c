#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <Block.h>

#include "Hash.h"

struct Hash {
	void *elements;
	size_t elem_size;
	size_t (^key)(void*);
	int (^compare)(void *, void*);
	void (^release)(void *);
};

static const size_t kHashValue = 127;	// This is also how many elements are in hash->elements

hash_t
CreateHash(size_t elem_size,
	   size_t (^get_key)(void *object),
	   int (^compare)(void *left, void *right),
	   void (^release)(void *))
{
	struct Hash *retval = calloc(1, sizeof(struct Hash));
	if (retval != NULL) {
		retval->elements = NULL;
		retval->elem_size = elem_size;
		retval->key = _Block_copy(get_key);
		retval->compare = _Block_copy(compare);
		if (release)
			retval->release = _Block_copy(release);
	}
	return (hash_t)retval;
}

void *
SearchHash(hash_t hashIn, void *key)
{
	void *retval = NULL;
	struct Hash *hash = hashIn;
	void **array;
	size_t indx;

	if (hash == NULL ||
		hash->elements == NULL) {
		goto done;
	}

	array = (void**)hash->elements;
	indx = hash->key(key) % kHashValue;
	if (array[indx] == NULL) {
		goto done;
	} else {
		size_t i = 0;
		void **list = (void**)array[indx];
		while (list[i] != NULL) {
			if (hash->compare(list[i], key) == 1) {
				retval = list[i];
			}
			i++;
		}
	}

done:
	return retval;
}

void
AddHashElement(hash_t hashIn, void *key)
{
	struct Hash *hash = hashIn;
	void **array;
	size_t bucket;

	bucket = hash->key(key) % kHashValue;
	if (hash->elements == NULL) {
		hash->elements = calloc(kHashValue, sizeof(void*));
	}

	array = (void**)hash->elements;
	if (array[bucket] == NULL) {
		void **tmp = calloc(2, sizeof(void*));
		tmp[0] = calloc(1, hash->elem_size);
		tmp[1] = NULL;
		memcpy(tmp[0], key, hash->elem_size);
		array[bucket] = (void*)tmp;
		if (tmp[1] != NULL)
			abort();
	} else {
		void **tmp = (void**)array[bucket];
		void **new_array = NULL;
		size_t link_size = 0;
		while (tmp[link_size] != 0) {
			link_size++;
		}
		new_array = realloc(tmp, hash->elem_size * (link_size + 2));
		new_array[link_size] = calloc(1, hash->elem_size);
		new_array[link_size + 1] = NULL;
		memcpy(new_array[link_size], key, hash->elem_size);
		array[bucket] = (void*)new_array;
	}
}

void
IterateHash(hash_t hashIn, int (^handler)(void *))
{
	struct Hash *hash = hashIn;

	if (hash &&
	    hash->elements) {
		size_t bucket;
		void **array = (void**)hash->elements;
		for (bucket = 0;
		     bucket < kHashValue;
		     bucket++) {
			if (array[bucket]) {
				void **list = (void**)array[bucket];
				size_t indx;
				for (indx = 0;
				     list[indx] != NULL;
				     indx++) {
					if (list[indx]) {
						if (handler(list[indx]) == 0)
							goto done;
					}
				}
			}
		}
	}
done:
	return;
}


void
DestroyHash(hash_t hashIn)
{
	struct Hash *hash = hashIn;

	if (hash) {
		if (hash->elements) {
			size_t bucket;
			void **array = (void**)hash->elements;
			IterateHash(hash, ^(void *ptr) {
					if (hash->release) hash->release(ptr);
					if (ptr) free(ptr);
					return 1;
			});
			for (bucket = 0;
			     bucket < kHashValue;
			     bucket++) {
				if (array[bucket])
					free(array[bucket]);
			}
			free(hash->elements);
		}
		free(hash);
	}
}

size_t
HashEntriesCount(hash_t hashIn)
{
	struct Hash *hash = hashIn;
	__block size_t retval = 0;

	IterateHash(hash, ^(void *ptr) {
			if (ptr) retval++;
			return 1;
		});

	return retval;
}
