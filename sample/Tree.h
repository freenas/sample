#ifndef TREE_H
# define TREE_H

struct TreeHelpers;

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
		   char* (^string)(void *));
Node_t *NodeAddValue(Node_t *level, void *value);
void ReleaseTree(Node_t *level);

void PrintTree(Node_t *level, int indent);

#endif /* TREE_H */
