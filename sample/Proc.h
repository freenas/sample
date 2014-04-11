#ifndef PROC_H
# define PROC_H

# include <sys/types.h>

# include "Hash.h"

struct SampleThread;

typedef struct SampleProc {
	pid_t	pid;
	const char	*name;
	const char	*pathname;
	size_t num_samples;
	hash_t	threads;
	size_t num_vmaps;
	void *mmaps;	// actually struct kinfo_vmentry*
} SampleProc_t;

SampleProc_t *FindProcess(hash_t hash, pid_t pid);
SampleProc_t *AddProcess(hash_t hash, pid_t pid);	// Creates (and returns) an empty process with pid
hash_t CreateProcessHash(void);	// Creates the hash for processes

/*
 * Find the thread in the process.
 * If the thread is not already associated with the process, it creates
 * the entry in the process' hash space, and returns a pointer to it.
 */
struct SampleThread *GetThread(SampleProc_t *proc, lwpid_t tid);

/*
 * Get the VM mapping information for a process.
 */
void ProcessGetVMMaps(SampleProc_t *proc);

#endif /* PROC_H */
