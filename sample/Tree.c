#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <libxo/xo.h>

#include <Block.h>

#include "Symbol.h"
#include "Tree.h"
#include "Keys.h"

typedef struct TreeHelpers {
	int	(^compare)(void *left, void *right);	// Standard compare, a la memcmp
	void*	(^retain)(void *);	// Reference counter.  May simply duplicate value
	void	(^release)(void *);	// Deallocate the object
	SampleInstance_t	(^instance)(void *);	// Value as a string; will be free'd when done
} TreeHelpers_t;

/*
 * Create a tree with the given functions.
 */
Node_t *
CreateTree(void* (^retain)(void *),
	   int (^compar)(void *, void*),
	   void (^rel)(void *),
	   SampleInstance_t (^instance)(void *))
{
	Node_t *retval = calloc(1, sizeof(*retval));
	TreeHelpers_t *helpers = calloc(1, sizeof(*helpers));
	
	helpers->retain = _Block_copy(retain);
	helpers->compare = _Block_copy(compar);
	helpers->release = _Block_copy(rel);
	helpers->instance = _Block_copy(instance);

	retval->helpers = helpers;

	return retval;
}

/*
 * Add a value to a node.  If the value already exists, increment
 * its count.  Return a pointer to the node.
 */
Node_t *
NodeAddValue(Node_t *level, void *value)
{
	size_t indx;
	Node_t *retval = NULL;
	TreeHelpers_t *helpers = level->helpers;
	Node_t *tmp;

	for (indx = 0;
	     indx < level->numChildren;
	     indx++) {
		if (helpers->compare(level->children[indx].value, value) == 0) {
			// A match, so increment it, and return it
			level->children[indx].count++;
			return &level->children[indx];
		}
	}
	tmp = realloc(level->children, sizeof(Node_t) * (level->numChildren + 1));
	if (tmp) {
		indx = level->numChildren++;
		level->children = tmp;
		level->children[indx].helpers = helpers;
		level->children[indx].value = helpers->retain(value);
		level->children[indx].count = 1;
		level->children[indx].numChildren = 0;
		level->children[indx].children = NULL;
		retval = &level->children[indx];
	}


done:
	return retval;
}

void
ReleaseTree(Node_t *tree)
{
	size_t indx;

	for (indx = 0;
	     indx < tree->numChildren;
	     indx++) {
		Node_t *cur = &tree->children[indx];
		ReleaseTree(cur);
	}
	if (tree->children)
		free(tree->children);

	if (tree->value) {
		tree->helpers->release(tree->value);
	} else {
		// For root, we free the tree itself
		_Block_release(tree->helpers->compare);
		_Block_release(tree->helpers->retain);
		_Block_release(tree->helpers->release);
		_Block_release(tree->helpers->instance);
		free(tree);
	}
}

void
PrintTree(Node_t *level, int indent)
{
	size_t indx;
	TreeHelpers_t *helpers = level->helpers;

#if 0
	if (level->value == NULL ||
	    level->numChildren == 0)
		return;
#endif
	
	if (level->value) {
		SampleInstance_t si = helpers->instance(level->value);
		
		// Sanity check:  if si.file is NULL we do nothing
		if (si.file) {
			char *fmt;

			xo_emit("{P:/%*s}{:" SAMPLE_COUNT_KEY "/%zu} "
				"{V,quotes:" SAMPLE_ADDR_KEY "/%p}",
				indent -1, "",
				level->count,
				si.addr);
			xo_emit(" ({:" SAMPLE_FILE_KEY "/%s} + "
				"{:" SAMPLE_OFFSET_KEY "/%llu})",
				si.file->pathname, (unsigned long long)si.file_offset);
#if 0
			// Not sure I need this, since pathname gets the mapped entry
			xo_emit("{V:file_offset/%llu}{V,quotes:file_base/%p}{V:file_len/%zu}",
				(long long)si.file->offset, si.file->base, si.file->len);
#endif
			if (si.symbol) {
				xo_emit(" [{:" SAMPLE_SYMBOL_KEY "/%s} + "
					"{:" SAMPLE_SYMOFF_KEY "/%llu}]",
					si.symbol, (unsigned long long)si.symbol_offset);
				free(si.symbol);
			}
			xo_emit("\n");
		}
	}
	if (level->numChildren) {
		xo_open_list(STACKS_LIST);
		xo_open_instance(STACKS_LIST);
		for (indx = 0;
		     indx < level->numChildren;
		     indx++) {
			Node_t *cur = &level->children[indx];
			PrintTree(cur, indent+1);
		}
		xo_close_instance(STACKS_LIST);
		xo_close_list(STACKS_LIST);
	}
	return;
}

#if 0
/*
 * Debugging/development code.
 */
int
main(int ac, char **av)
{
	int indx;
	Node_t *root;

	root = CreateTree(^(void *val) {
			return (void*)strdup((char*)val);
		}, ^(void *left, void *right) {
			return (int)strcmp((char*)left, (char*)right);
		}, ^(void *val) {
			free(val);
		}, ^(void *val) {
			return (char*)strdup((char*)val);
		});

	Node_t *tmp = root;

#if 0
	for (indx = 1;
	     indx < ac;
	     indx++) {
		tmp = NodeAddValue(tmp, av[indx]);
	}
#else
	NodeAddValue(NodeAddValue(root, "1"), "2");
	NodeAddValue(root, "1");
	NodeAddValue(NodeAddValue(NodeAddValue(root, "1"), "2"), "3");
	NodeAddValue(root, "2");
#endif

	PrintTree(root, 0);
	ReleaseTree(root);

	return 0;
	
}
#endif
