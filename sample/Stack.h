#ifndef STACK_H
# define STACK_H

# include "sample.h"

typedef struct StackStructure {
	size_t count;
	void *stacks[0];
} Stack_t;

Stack_t *CreateStack(kern_sample_t *);

void ReleaseStack(Stack_t *);

#endif /* STACK_H */
