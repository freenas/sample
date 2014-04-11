#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <kvm.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <machine/reg.h>

#include "Hash.h"
#include "Proc.h"
#include "Thread.h"
#include "Stack.h"
#include "Tree.h"
#include "Symbol.h"

#ifndef KERN_PROC_PROFILE
# define KERN_PROC_PROFILE       42      /* get stack dumps for kernel and user */
#endif

int debug = 0;
int verbose = 0;

static int
sampling_start(int ms)
{
        return syscall(545, ms);
}

static int
sampling_stop(void)
{
        return syscall(546);
}

static int
sampling_read(void *buffer, size_t buffer_size)
{
        return __syscall(547, buffer, buffer_size);
}

static int
iterate_procs(kvm_t *kvm, void (^handler)(struct kinfo_proc *))
{
	struct kinfo_proc *procs = NULL;
	int num_procs;

	procs = kvm_getprocs(kvm, KERN_PROC_PROC, 0, &num_procs);
	if (procs) {
		size_t i;
		for (i = 0; i < num_procs; i++) {
			handler(procs + i);
		}
	} else {
		return -1;
	}
	return 0;
}

static const char *
GetProcessPathname(pid_t pid)
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid };
	char pathname[MAXPATHLEN + 1] = { 0 };
	int rv;
	size_t size = sizeof(pathname);
	rv = sysctl(mib, 4, pathname, &size, NULL, 0);
	if (rv != -1) {
		if (pathname[0]) {
			return strdup(pathname);
		}
	}
	return NULL;
}

static uint8_t profile_buffer[128 * 1024];	// 128k should be enough
static void
CollectSampleInformation(SampleProc_t *proc)
{
	size_t profile_size = sizeof(profile_buffer);
	int rv;
	int stack_mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PROFILE, proc->pid };

	if (proc->pid == getpid()) {
		return;	// Can't trace ourselves?
	}

#if 0
	if (proc->pathname == NULL) {
		fprintf(stderr, "Not tracking kernel path %s\n", proc->name);
		return;
	}
#endif

	if (proc->mmaps == NULL) {
		ProcessGetVMMaps(proc);
	}

	rv = sysctl(stack_mib, 4, profile_buffer, &profile_size, NULL, 0);
	if (rv != -1) {
		struct kinfo_sample *cur = (void*)profile_buffer,
			*end = (void*)(profile_buffer + profile_size);
		while (cur < end) {
			Stack_t *stack;
			SampleThread_t *thread = GetThread(proc, cur->kkpr_tid);
			size_t size = sizeof(struct kinfo_sample) + cur->kkpr_depth * sizeof(caddr_t);
			stack = CreateStack(cur);
			if (stack) {
				ThreadAddStack(thread, stack);
			}
			cur = (void*)(((uint8_t*)cur) + size);
		}
	}
}

static void
usage(void)
{
	errx(1, "usage:  [-n sample_count] [-s sample_duration] [-p pid]\n"
	     "\tsample duration in ms (default 10)");
}

int
main(int ac, char **av)
{
	kvm_t *kvm;
	int num_syms;
	hash_t ProcHash;
	int i;
	struct timespec dur = { 0 };
	uint8_t *sample_buffer = NULL;
	uint32_t sample_duration = 10;	// in ms
	uint32_t sample_count = 100;
	pid_t target = 0;	// 0 means all processes
	static const int kSampleBufferSize = 1024 * 1024;
	int symbolicate = 0;

	while ((i = getopt(ac, av, "n:s:p:dvS")) != -1) {
		switch (i) {
		case 'S':
			symbolicate = 1;
			break;
		case 'n':
			sample_count = atoi(optarg);
			break;
		case 's':
			sample_duration = atoi(optarg);
			break;
		case 'p':
			target = atoi(optarg);
			break;
		case 'd':
			debug++;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

//	if (target == 0) {
		kvm = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
		if (kvm == NULL) {
			err(1, "could not create kvm");
		}
//	}

	ProcHash = CreateProcessHash();

	dur.tv_sec = (sample_duration / 1000);
	dur.tv_nsec = (sample_duration % 1000) * 1000000;

	sample_buffer = malloc(kSampleBufferSize);	// hack, should be configurable

	if (sample_buffer)
		(void)sampling_start(sample_duration);

	for (i = 0;
	     i < sample_count;
	     i++) {
		int num_samples;

		void (^handler)(struct kinfo_proc *proc) = ^(struct kinfo_proc *proc) {
			SampleProc_t *p;
			if (target && proc->ki_pid != target)
				return;
			p = FindProcess(ProcHash, proc->ki_pid);
			if (p == NULL) {
				const char *pathname = GetProcessPathname(proc->ki_pid);
				p = AddProcess(ProcHash, proc->ki_pid);
				p->pathname = pathname;
				p->name = strdup(proc->ki_comm);
			} else {
			}
			p->num_samples++;
			CollectSampleInformation(p);
		};
		fprintf(stderr, "whee\n");
		if (iterate_procs(kvm, handler) == -1) {
			err(1, "iterate_procs");
		}
		
		if ((num_samples = sampling_read(sample_buffer, kSampleBufferSize)) > 0) {
			kern_sample_t *cur_sample = (void*)sample_buffer;
			int indx;

			fprintf(stderr, "Got %u kernel samples\n", num_samples);

			for (indx = 0; indx < num_samples; indx++) {
				uint8_t *ptr = (void*)cur_sample;
				SampleProc_t *p;
				p = FindProcess(ProcHash, cur_sample->pid);
				if (p != NULL) {
					SampleThread_t *thread = GetThread(p, cur_sample->tid);
					if (thread) {
						Stack_t *stack = CreateStackFromSample(cur_sample);
						if (stack) {
							ThreadAddStack(thread, stack);
						}
					}
				}
				ptr += sizeof(kern_sample_t) + sizeof(caddr_t) * cur_sample->num_pcs;
				cur_sample = (void*)ptr;
			}
		}

		if (nanosleep(&dur, NULL) != 0) {
			warn("nanosleep interrupted, breaking");
			break;
		}
	}

	if (sample_buffer) {
		sampling_stop();
		free(sample_buffer);
	}

	SymbolPool_t kernelPool = CreateSymbolPool();
        if (kernelPool) {
                int mod_id = 0;
                while ((mod_id = kldnext(mod_id)) > 0) {
                        struct kld_file_stat mod_stat = { .version = sizeof(mod_stat) };
                        if (kldstat(mod_id, &mod_stat) != -1) {
                                SymbolFile_t *f = CreateSymbolFile(mod_stat.pathname,
                                                                   0, // Is this right?
                                                                   mod_stat.address,
                                                                   mod_stat.size);
                                if (f) {
                                        (void)AddSymbolFile(kernelPool, f);
                                        ReleaseSymbolFile(f);
                                }
                        } else {
                                warn("Could not stat kernel mod_id %d", mod_id);
                        }
                }
        }

	IterateHash(ProcHash, ^(void *object) {
			SampleProc_t *proc = object;
			size_t vmIndex = 0;
			printf("Process %d (%s, pathname %s):\n%zu samples\n", proc->pid, proc->name, proc->pathname ? proc->pathname : "unknown", proc->num_samples);
			IterateHash(proc->threads, ^(void *inner) {
					SampleThread_t *thread = inner;
					SymbolPool_t pool;
					pool = CreateSymbolPool();

					if (proc->num_vmaps > 0) {
                                                struct kinfo_vmentry *vme = proc->mmaps;
                                                size_t vmIndex;
                        
                                                for (vmIndex = 0;
                                                     vmIndex < proc->num_vmaps;
                                                     vmIndex++) {
                                                        if (vme[vmIndex].kve_protection & KVME_PROT_EXEC &&
                                                            vme[vmIndex].kve_type == KVME_TYPE_VNODE &&
                                                            vme[vmIndex].kve_path[0]) {
								SymbolFile_t *f = CreateSymbolFile(vme[vmIndex].kve_path,
												   vme[vmIndex].kve_offset,
												   (void*)vme[vmIndex].kve_start,
												   (size_t)(vme[vmIndex].kve_end - vme[vmIndex].kve_start));
								if (f) {
									(void)AddSymbolFile(pool, f);
									ReleaseSymbolFile(f);
								}
							}
						}
					}
					if (pool) {
						if (kernelPool) {
							AddSymbolPool(pool, kernelPool);
						}
					}

					if (thread->numStacks > 0) {
						Node_t *root;
						printf("\nThread ID %u\n", thread->tid);
						root = CreateTree(^(void *val) {
								return (void*)val;
							}, ^(void *left, void *right) {
								vm_offset_t l = (vm_offset_t)left,
									r = (vm_offset_t)right;
								if (l == r)
									return 0;
								if (l < r)
									return -1;
								if (l > r)
									return 1;
								return 2;
							}, ^(void *val) {
								return;
							}, ^(void *val) {
								char *retval;
								off_t off;
								if (symbolicate == 0) {
									SymbolFile_t *sf = NULL;
									if (pool) {
										sf = FindSymbolFileByAddress(pool, val, &off);
									}
									if (sf) {
										asprintf(&retval, "%p (%s + %llu)", val, sf->pathname, (long long)off);
									} else {
										asprintf(&retval, "%p", val);
									}
								} else {
									char *tmp;
									tmp = FindSymbolForAddress(pool, val, &off);
									if (tmp) {
										asprintf(&retval, "%p (%s + %llu)", val, tmp, (long long)off);
										free(tmp);
									} else {
										asprintf(&retval, "%p", val);
									}
								}
								return retval;
							});
						if (root) {
							int stackNum;
							Stack_t **stacks = (Stack_t**)thread->stacks;
							for (stackNum = 0;
							     stackNum < thread->numStacks;
							     stackNum++) {
								Stack_t *curStack = stacks[stackNum];
								int stackLevel;
								Node_t *level = root;

								for (stackLevel = 0;
								     stackLevel < curStack->count;
								     stackLevel++) {
									char *trace = curStack->stacks[stackLevel];
									level = NodeAddValue(level, trace);
								}
							}
							PrintTree(root, 1);
						}
					}
					return 1;
				});
			if (proc->num_vmaps > 0) {
				struct kinfo_vmentry *vme = proc->mmaps;
				printf("\nMapped Files:\n");
				printf("\tStart\tEnd\tFile\n");
				for (vmIndex = 0;
				     vmIndex < proc->num_vmaps;
				     vmIndex++) {
					if (vme[vmIndex].kve_vn_fileid) {
						printf("\t%#llx\t%#llx\t%s\n",
						       (long long)vme[vmIndex].kve_start,
						       (long long)vme[vmIndex].kve_end,
						       vme[vmIndex].kve_path);
					}
				}
			}
			printf("\n");
			return 1;
		});
	kvm_close(kvm);
	DestroyHash(ProcHash);

	return 0;
}
