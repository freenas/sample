#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include <sys/types.h>

#include "Proc.h"
#include "Thread.h"
#include "Stack.h"

void
ThreadAddStack(SampleThread_t *thread, struct StackStructure *stack)
{
	void **tmp;
	tmp = (void**)realloc(thread->stacks, sizeof(stack) * (thread->numStacks + 1));
	thread->stacks = tmp;
	thread->stacks[thread->numStacks++] = stack;
}
