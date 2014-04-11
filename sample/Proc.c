#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <sys/types.h>
#include <libutil.h>

#include "Hash.h"
#include "Proc.h"
#include "Thread.h"
#include "Stack.h"

hash_t
CreateProcessHash(void)
{
	hash_t retval = NULL;
	retval = CreateHash(sizeof(SampleProc_t),
			    ^(void *key) {
				    return (size_t)((SampleProc_t*)key)->pid;
			    },
			    ^(void *left, void *right) {
				    SampleProc_t *l = left, *r = right;
				    return (l->pid == r->pid) ? 1 : 0;
			    },
			    ^(void *ptr) {
				    SampleProc_t *proc = ptr;
				    if (proc->name) free((void*)proc->name);
				    if (proc->pathname) free((void*)proc->pathname);
				    if (proc->threads) DestroyHash(proc->threads);
				    if (proc->mmaps) free(proc->mmaps);
			    });
	return retval;
}

SampleProc_t *
FindProcess(hash_t hash, pid_t pid)
{
	SampleProc_t tKey = { 0 }, *retval;
	tKey.pid = pid;

	retval = SearchHash(hash, &tKey);
	return retval;
}

SampleProc_t *
AddProcess(hash_t hash, pid_t pid)
{
	SampleProc_t tKey = { 0 }, *retval = NULL;
	tKey.pid = pid;
	AddHashElement(hash, &tKey);
	return FindProcess(hash, pid);
}

static hash_t
CreateThreadHash(void)
{
	hash_t retval = NULL;
	retval = CreateHash(sizeof(SampleThread_t),
			    ^(void *key) {
				    return (size_t)((SampleThread_t*)key)->tid;
			    },
			    ^(void *left, void *right) {
				    SampleThread_t *l = left, *r = right;
				    return (l->tid == r->tid) ? 1 : 0;
			    },
			    ^(void *ptr) {
				    SampleThread_t *thread = ptr;
				    size_t stackNum;

				    for (stackNum = 0;
					 stackNum < thread->numStacks;
					 stackNum++) {
					    ReleaseStack(thread->stacks[stackNum]);
				    }
			    });
	return retval;
}

SampleThread_t *
GetThread(SampleProc_t *proc, lwpid_t tid)
{
	SampleThread_t *retval = NULL;
	SampleThread_t tmp = { .tid = tid };

	if (proc->threads == NULL) {
		proc->threads = CreateThreadHash();
	}

	retval = SearchHash(proc->threads, &tmp);
	if (retval == NULL) {
		// Add it to the hash
		AddHashElement(proc->threads, &tmp);
		retval = SearchHash(proc->threads, &tmp);
		retval->proc = proc;
	}
	return retval;
}

void
ProcessGetVMMaps(SampleProc_t *proc)
{
	int tmp = 0;
	if (proc->mmaps) {
		free(proc->mmaps);
		proc->num_vmaps = 0;
	}
	proc->mmaps = kinfo_getvmmap(proc->pid, &tmp);
	proc->num_vmaps = tmp;
}
