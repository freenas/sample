#ifndef THREAD_H
# define THREAD_H

# include <sys/types.h>

struct SampleProc;
struct StackStructure;

typedef struct SampleThread {
	struct SampleProc *proc;
	lwpid_t tid;
	size_t numStacks;
	void **stacks;
} SampleThread_t;

void ThreadAddStack(SampleThread_t *thread, struct StackStructure *);

#endif /* THREAD_H */
