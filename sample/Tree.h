#ifndef TREE_H
# define TREE_H

struct TreeHelpers;
struct SymbolFile;

typedef struct SampleInstance {
	void *addr;
	struct SymbolFile *file;	// Can get path, address, size, etc.
	off_t file_offset;	// Offset into the file
	char *symbol;	// May be NULL
	off_t symbol_offset;	// Only valid if symbol is non-NULL
} SampleInstance_t;

typedef struct NodeStructure {
	struct TreeHelpers	*helpers;	// All nodes are on a tree
	void *value;	// Will be NULL for the root of the tree
	size_t count;	// Number of times it shows up
	size_t numChildren;
	struct NodeStructure *children;
} Node_t;

Node_t *CreateTree(void* (^retain)(void*),
		   int (^compare)(void *, void *),
		   void (^release)(void *),
		   SampleInstance_t (^instance)(void *));
Node_t *NodeAddValue(Node_t *level, void *value);
void ReleaseTree(Node_t *level);

void PrintTree(Node_t *level, int indent);

#endif /* TREE_H */
