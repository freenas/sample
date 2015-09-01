#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/taskqueue.h>

#include <sys/user.h>
#include <sys/proc.h>

#include <machine/cpu.h>
#include <machine/atomic.h>

#include "sample.h"

#define KERN_SAMPLE_MAX_STACK   256     // 256 levels deep seems enough for now

#define STAGING_BUFFER_SIZE     (8 * 1024)      // 8Kbytes for temporary stack

typedef struct {
        struct mtx sample_spin; // Spin lock
        size_t  sample_size;    // Total size of buffer
	int32_t	sample_count;	// How many to do -- counts down to 0
        struct timeval next_time;
        struct timeval sample_ms;      // Milliseconds between samples
        struct callout  sample_callout;
	struct timeout_task	sample_task;	// Like the callout, but for taskqueue
        void    *temp_buffer;   // Staging area to get a sample's stacks.
        uint32_t        num_dropped;
        kern_sample_t   *head;
        kern_sample_t   *tail;
        kern_sample_t   samples[0];
} kern_sample_set_t;

/*
 * The main structure describing the current samples being taken.
 * There is one more sample set than CPU -- the last one is the
 * samples for the non-running threads.
 */

struct kern_sample_struct {
        size_t  s_ncpu; // How many CPU slots
        kern_sample_set_t       *cpu_sample_sets[0];
};


static MALLOC_DEFINE(M_SAMPLE, "kern_sample", "Kernel-level sampling");

static struct mtx sample_lock;
static struct cdev *sample_dev;
static int is_open;	// Only one open at a time
static struct kern_sample_struct *kern_samples;
static int sample_data_ready;	// Used for tsleep and wakeup

// File-local functions

static int sample_open(struct cdev *dev, int oflags, int devtype, struct thread *td);
static int sample_close(struct cdev *dev, int fflag, int devtype, struct thread *td);
static int sample_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td);
static int sample_read(struct cdev *dev, struct uio *uio, int ioflag);
static int sample_write(struct cdev *dev, struct uio *uio, int ioflag);

static struct cdevsw sample_cdevsw = {
	.d_version = D_VERSION,
	.d_open = sample_open,
	.d_close = sample_close,
	.d_read = sample_read,
	.d_write = sample_write,
	.d_ioctl = sample_ioctl,
	.d_name = "sample"
};

/*
 * Extract a sample from a sample_set.  Since the buffer is a circular
 * buffer, the value may wrap.  This function may not be called from
 * the handler (since that is executing in interrupt context).
 *
 * If there are any samples, it will allocate a buffer using malloc (the
 * caller must free it), and set *sample to that value.  If there are
 * no samples, *sample will be set to NULL.
 *
 * It returns 0 on success, and an errno on error.
 *
 * Only get_sample modifies sample_set_t->head.
 *
 */
static inline size_t
get_sample_size_from_ring_buffer(kern_sample_set_t *set, kern_sample_t *head)
{
	size_t retval = 0;

#if SAMPLE_DEBUG
	uprintf("%s(%d):  head->num_pcs = %d\n", __FUNCTION__, __LINE__, head->num_pcs);
#endif
        retval = sizeof(*head) + sizeof(caddr_t) * head->num_pcs;
        return retval;
}

static int
get_sample(kern_sample_set_t *sample_set, kern_sample_t *buffer, size_t buffer_size)
{
        uint8_t *head, *tail, *start, *end;
        int error = 0;
        size_t sample_size;

#if SAMPLE_DEBUG > 5
	uprintf("%s(%d)\n", __FUNCTION__, __LINE__);
#endif

        mtx_lock_spin(&sample_set->sample_spin);
        head = (uint8_t*)sample_set->head;
        tail = (uint8_t*)sample_set->tail;

        if (head == tail) {
                // No entries
                error = ENOENT;
                goto done;
        }
        sample_size = get_sample_size_from_ring_buffer(sample_set, (kern_sample_t*)head);
        KASSERT((sample_size > sizeof(kern_sample_t)), ("sample size %zu is too small", sample_size));

        if (sample_size > buffer_size) {
#if SAMPLE_DEBUG
		uprintf("%s(%d):  sample_size = %zu, buffer_size = %zu\n", __FUNCTION__, __LINE__, sample_size, buffer_size);
#endif
                error = ENOSPC;
                goto done;
        }

        start = (uint8_t*)sample_set->samples;
        end = start + sample_set->sample_size;

        if (head < tail) {
                if (sample_size > (tail - head)) {
                        /*
                         * This should not have happened.  It means the buffer
                         * is corrupt.  I should probably indicate this somehow.
                         */
                        error = EINVAL;
                        goto done;
                }
                bcopy(head, buffer, sample_size);
                head += sample_size;
        }  else {
                // It wraps, so a bit more complicated
                size_t avail = end - head, amt;

                avail += tail - start;
                if (sample_size > avail) {
                        error = EINVAL;
                        goto done;
                }
                amt = MIN(sample_size, end - head);
                bcopy(head, buffer, amt);
                if (amt == sample_size) {
                        head += amt;
                } else {
                        bcopy(start, ((uint8_t*)buffer) + amt, sample_size - amt);
                        head = start + (sample_size - amt);
                }
        }
        sample_set->head = (void*)head;

done:
        mtx_unlock_spin(&sample_set->sample_spin);

        return (error);
}

/*
 * Add the blob of sample_in to sample_set->samples.
 * This is a circular buffer, so the data may wrap.
 * If adding the blob would go past sample_set->head,
 * then this is a dropped sample, and we increment
 * the appropriate field.
 *
 * Only add_sample modifies sample_set->tail, and only
 * one caller invokes us.
 */
static void __unused
add_sample(kern_sample_set_t *sample_set,
           void *sample_in,
           size_t sample_size)
{
        uint8_t *sample = sample_in;
        uint8_t *head, *tail, *start, *end;

        mtx_lock_spin(&sample_set->sample_spin);
        head = (uint8_t*)sample_set->head;
        tail = (uint8_t*)sample_set->tail;

        start = (uint8_t*)sample_set->samples;
        end = start + sample_set->sample_size;

        if (head > tail) {
                // We don't have to worry about wrapping
                if (sample_size > (head - tail)) {
                        atomic_add_32(&sample_set->num_dropped, 1);
                } else {
                        bcopy(sample, tail, sample_size);
                        sample_set->tail = (void*)(tail + sample_size);
                }
        } else {
                // We may have to wrap
                size_t avail, amt;

                avail = end - tail;
                avail += head - start;

                if (sample_size > avail) {
                        atomic_add_32(&sample_set->num_dropped, 1);
                } else {
                        amt = MIN(sample_size, end - tail);
                        bcopy(sample, tail, amt);
                        if (amt != sample_size) {
                                bcopy(sample + amt, start, sample_size - amt);
                                sample_set->tail = (void*)(start + (sample_size - amt));
                        } else {
                                sample_set->tail = (void*)(tail + sample_size);
                        }
                }
        }
        mtx_unlock_spin(&sample_set->sample_spin);
}

static void __unused
sample_cpu_handler(void *arg)
{
        kern_sample_set_t *ctx = arg;
        struct timeval now;

#if SAMPLE_DEBUG > 1
	printf("%s(%p):  CPU %u, ctx->head = %p, ctx->tail = %p, ctx->sample_size = %zu\n", __FUNCTION__, arg, PCPU_GET(cpuid), ctx->head, ctx->tail, ctx->sample_size);

#endif
        /*
         * Since I'm not sure how often we actually get called, let's
         * check to see if we're past when the next call should be.
         */
        getmicrouptime(&now);
        if (timevalcmp(&now, &ctx->next_time, >=)) {
                kern_sample_t *samp = ctx->temp_buffer;

                /*
                 * Figure out the next firing time
                 */
                ctx->next_time = now;
                timevaladd(&ctx->next_time, &ctx->sample_ms);

                samp->pid = curthread->td_proc->p_pid;
                samp->tid = curthread->td_tid;
		samp->cpuid = PCPU_GET(cpuid);
		samp->sample_type = SAMPLE_TYPE_RUNNING;
#if SAMPLE_DEBUG > 2
		printf("%s(%d):  sampe = {pid %u, tid %u, cpuid %d, type %d}\n", __FUNCTION__, __LINE__, samp->pid, samp->tid, samp->cpuid, samp->sample_type);
#endif
                getnanouptime(&samp->timestamp);
                samp->num_pcs = md_stack_capture_curthread(samp->pc, (STAGING_BUFFER_SIZE - offsetof(kern_sample_t, pc)) / sizeof(caddr_t));
		if (samp->num_pcs > 0) {
			add_sample(ctx, samp, get_sample_size_from_ring_buffer(NULL, samp));
		} else {
#if SAMPLE_DEBUG > 1
			printf("%s(%d):  Sample for <pid %u, tid %u> on cpu %d was empty\n", __FUNCTION__, __LINE__, samp->pid, samp->tid, samp->cpuid);
#endif
		}
		mtx_lock_spin(&ctx->sample_spin);
		if (ctx->sample_count > 0)
			ctx->sample_count--;
		mtx_unlock_spin(&ctx->sample_spin);
        }
       
	wakeup(&sample_data_ready);

	mtx_lock_spin(&ctx->sample_spin);
	if (ctx->sample_count > 0) {
#if SAMPLE_DEBUG > 1
		struct timespec now;
		getnanouptime(&now);
		printf("%s(%d):  CPU %d, sample_count = %u, now = <%lu, %lu>\n", __FUNCTION__, __LINE__, PCPU_GET(cpuid), ctx->sample_count, now.tv_sec, now.tv_nsec);
#endif
#ifdef C_DIRECT_EXEC
		callout_reset_sbt_on(&ctx->sample_callout, tvtosbt(ctx->sample_ms), 1,
				     sample_cpu_handler, arg, PCPU_GET(cpuid), C_DIRECT_EXEC);
#else
		int ticks_ms = tvtohz(&ctx->sample_ms);
		callout_reset_on(&ctx->sample_callout, ticks_ms, sample_cpu_handler, ctx, PCPU_GET(cpuid));
#endif
	}
	mtx_unlock_spin(&ctx->sample_spin);
	return;
}

/*
 * This is to iterate through all the threads, and only
 * look at threads that are sleeping (that is, not swapped
 * out, and not running).
 *
 * Unlike the per-cpu one, it will get many sets of samples.
 */
static void
sample_sleeping_task(void *arg, int pending)
{
	kern_sample_set_t *ctx = arg;
	struct proc *p;

#if SAMPLE_DEBUG > 2
	printf("%s(%d)\n", __FUNCTION__, __LINE__);
#endif

	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		struct thread *td;

		PROC_LOCK(p);

		if (p->p_state == PRS_NEW) {
			PROC_UNLOCK(p);
			continue;
		}
		FOREACH_THREAD_IN_PROC(p, td) {
			kern_sample_t *samp = (void*)ctx->temp_buffer;
			size_t depth;

			if (TD_IS_SWAPPED(td) ||
			    TD_IS_RUNNING(td)) {
				continue;
			}

			depth = md_stack_capture_forthread(td, samp->pc, (STAGING_BUFFER_SIZE - offsetof(kern_sample_t, pc)) / sizeof(caddr_t));
#if SAMPLE_DEBUG > 2
			printf("%s(%d):  pid %u tid %u, depth = %zu\n", __FUNCTION__, __LINE__, td->td_proc->p_pid, td->td_tid, depth);
#endif

			if (depth > 0) {
				samp->pid = td->td_proc->p_pid;
				samp->tid = td->td_tid;
				samp->cpuid = td->td_oncpu;
				samp->sample_type = SAMPLE_TYPE_SLEEPING;
				getnanouptime(&samp->timestamp);
				samp->num_pcs = depth;
#if SAMPLE_DEBUG > 2
				printf("%s(%d):  sampe = {pid %u, tid %u, cpuid %d, type %d}\n", __FUNCTION__, __LINE__, samp->pid, samp->tid, samp->cpuid, samp->sample_type);
				printf("%s(%d):  sample size = %zu\n", __FUNCTION__, __LINE__, sizeof(*samp) + sizeof(caddr_t) * depth);
#endif
				add_sample(ctx, samp, sizeof(*samp) + sizeof(caddr_t) * depth);
			}
		}
		PROC_UNLOCK(p);
	}
	sx_sunlock(&allproc_lock);
	wakeup(&sample_data_ready);
	mtx_lock_spin(&ctx->sample_spin);
//	printf("sleeping sample count %u\n", ctx->sample_count);
	if (ctx->sample_count-- > 1) {
		int ticks_ms = tvtohz(&ctx->sample_ms);
		taskqueue_enqueue_timeout(taskqueue_thread,
					  &ctx->sample_task,
					  ticks_ms);
	}
	mtx_unlock_spin(&ctx->sample_spin);
	return;
}

// Any locking should be done before we get here
static void
release_sample_data(void)
{
	if (kern_samples != NULL) {
                size_t cpu_index;

                for (cpu_index = 0;
                     cpu_index < kern_samples->s_ncpu;
                     cpu_index++) {
                        kern_sample_set_t *cur_set;

                        cur_set = kern_samples->cpu_sample_sets[cpu_index];
#if SAMPLE_DEBUG
			uprintf("%s(%d):  Calling callout_drain now\n", __FUNCTION__, __LINE__);
#endif
			mtx_lock_spin(&cur_set->sample_spin);
			cur_set->sample_count = 0;
			mtx_unlock_spin(&cur_set->sample_spin);
			if (cpu_index < kern_samples->s_ncpu - 1)
				callout_drain(&cur_set->sample_callout);
			else
				taskqueue_drain_timeout(taskqueue_thread, &cur_set->sample_task);
			
			mtx_destroy(&cur_set->sample_spin);
			if (cur_set->temp_buffer)
				free(cur_set->temp_buffer, M_SAMPLE);
			free(cur_set, M_SAMPLE);
                }
                free(kern_samples, M_SAMPLE);
                kern_samples = NULL;
        }
}
static int
sample_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	int error = 0;

#if SAMPLE_DEBUG
	uprintf("%s(%p, %#o, %d, %p)\n", __FUNCTION__, dev, oflags, devtype, td);
#endif
	mtx_lock(&sample_lock);

	if (is_open != 0) {
		return EBUSY;
		goto done;
	}

	if (kern_samples != NULL) {
		error = EBUSY;
		goto done;
	}
	is_open = 1;

done:
	mtx_unlock(&sample_lock);
	return error;
}

static int
sample_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
#if SAMPLE_DEBUG
	uprintf("%s(%p, %#o, %d, %p)\n", __FUNCTION__, dev, fflag, devtype, td);
#endif
	mtx_lock(&sample_lock);
	is_open = 0;

	release_sample_data();
	mtx_unlock(&sample_lock);

	return 0;
}

static int
sample_ioctl(struct cdev *dev,
	     u_long cmd,
	     caddr_t data,
	     int fflag,
	     struct thread *td)
{
	int retval = 0;

	mtx_lock(&sample_lock);

	switch (cmd) {
	case KSIOC_STOP:
	{
		if (kern_samples != NULL) {
			release_sample_data();
		}
	}
	break;
	case KSIOC_START:
	{
		if (kern_samples == NULL) {
			int ncpus = mp_ncpus + 1;
			int cur_cpu = 0;
			size_t buffer_size = 1024 * 1024;	// Per-cpu buffer size
			size_t sample_buffer_size;
			int cpu_index;
			struct timeval sample_ms = { 0 };
			struct ksample_opts *opts = (void*)data;
			int out_of_mem = 0;

			if (opts->milliseconds <= 0 ||
			    opts->milliseconds >= 1000) {
				retval = EINVAL;
				goto done;
			}
			if (opts->count == 0) {
				retval = EINVAL;
				goto done;
			}

#if SAMPLE_DEBUG
			printf("start_sampling:  opts = <%u, %u>\n", opts->milliseconds, opts->count);
#endif

			sample_ms.tv_usec = opts->milliseconds * 1000;	// 1ms = 1000 usecs

			kern_samples = malloc(sizeof(struct kern_sample_struct) + sizeof(kern_sample_set_t) * ncpus,
					      M_SAMPLE, M_WAITOK | M_ZERO);
			if (kern_samples == NULL) {
				retval = ENOMEM;
				goto done;
			}
			kern_samples->s_ncpu = ncpus;
			sample_buffer_size = buffer_size - sizeof(kern_sample_set_t);

			for (cpu_index = 0; cpu_index < ncpus; cpu_index++) {
				// Allocate each of the buffers for sampling
				void *tmp = malloc(buffer_size, M_SAMPLE, M_WAITOK | M_ZERO);
				if (tmp == NULL) {
					out_of_mem = 1;
					break;
				}
				kern_samples->cpu_sample_sets[cpu_index] = tmp;
			}
			if (out_of_mem) {
				// Blast it, we ran out of memory
#if SAMPLE_DEBUG
				uprintf("%s(%d): out of memory\n", __FUNCTION__, __LINE__);
#endif
				for (cpu_index--; cpu_index >= 0; cpu_index--) {
					free(kern_samples->cpu_sample_sets[cpu_index], M_SAMPLE);
					kern_samples->cpu_sample_sets[cpu_index] = NULL;
				}
#if SAMPLE_DEBUG > 2
				uprintf("%s(%d)\n", __FUNCTION__, __LINE__);
#endif

				free(kern_samples, M_SAMPLE);
				kern_samples = NULL;
				retval = ENOMEM;
				goto done;
			}
			// Now initialize each of the entries
			uprintf("%s(%d):  opts->count = %d\n", __FUNCTION__, __LINE__, opts->count);
			
			for (cpu_index = 0, cur_cpu = CPU_FIRST(); cpu_index < ncpus; cpu_index++, cur_cpu = CPU_NEXT(cur_cpu)) {
				kern_sample_set_t *cur_set = kern_samples->cpu_sample_sets[cpu_index];
				mtx_init(&cur_set->sample_spin, "Sampling spin lock", NULL, MTX_SPIN);
				cur_set->sample_size = sample_buffer_size;
				cur_set->head = cur_set->tail = cur_set->samples;
				cur_set->sample_ms = sample_ms;
				cur_set->sample_count = opts->count;
				cur_set->temp_buffer = malloc(STAGING_BUFFER_SIZE, M_SAMPLE, M_WAITOK);
				callout_init(&cur_set->sample_callout, CALLOUT_MPSAFE);

				if (cpu_index < (ncpus - 1)) {
#ifdef C_DIRECT_EXEC
					callout_reset_sbt_on(&cur_set->sample_callout,
							     tvtosbt(sample_ms), 1,
							     sample_cpu_handler, cur_set, cur_cpu, 0);
#else
					int ticks_ms = tvtohz(&sample_ms);
					callout_reset_on(&cur_set->sample_callout, ticks_ms, sample_cpu_handler, cur_set, cur_cpu);
#endif
				} else {
					int ticks_ms = tvtohz(&sample_ms);
					
					TIMEOUT_TASK_INIT(taskqueue_thread,
							  &cur_set->sample_task,
							  1,
							  sample_sleeping_task,
							  cur_set);
					taskqueue_enqueue_timeout(taskqueue_thread,
								  &cur_set->sample_task,
								  ticks_ms);
//					callout_reset(&cur_set->sample_callout, ticks_ms, sample_sleeping_handler, cur_set);
				}
			}
		} else {
			retval = EBUSY;
		}
		goto done;
	}
	break;
	default:
		retval = ENOTTY;
	}
done:

	mtx_unlock(&sample_lock);
	return retval;
}

/*
 * Read data from the sample queues.
 *
 */
static int
sample_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	int error = 0;
	kern_sample_t *temp_sample = NULL;
	int samples_left;
	size_t start = uio->uio_resid;

	/*
	 * CHECKME
	 * Is there a better way to do what I want here?
	 * I'm using start and samples_left to see if we want
	 * to exit the loop in the caller.  I don't want to wait
	 * to fill up the buffer, but if all of the currently-recorded
	 * samples have been gotten, I want to return from read().
	 * If there are no samples left, I always want to return either
	 * 0 or however many have been read.
	 * If there are samples left, and O_NONBLOCK has not been given,
	 * then I want to wait until there are some more samples.
	 * If there are samples left, and O_NONBLOCK has been given, then
	 * read should return 0.
	 *
	 * So how would the caller distinguish between no samples left,
	 * and no samples currently available?
	 */
//	uprintf("%s(%d)\n", __FUNCTION__, __LINE__);

start_over:
	mtx_lock(&sample_lock);
	samples_left = 0;
//	uprintf("%s(%d)\n", __FUNCTION__, __LINE__);
	if (is_open == 0) {
		error = EBADF;
		goto done;
	}

	if (kern_samples == NULL)  {
		// Nothing to do
		goto done;
	}

	temp_sample = malloc(STAGING_BUFFER_SIZE, M_TEMP, M_WAITOK);
	if (temp_sample == NULL) {
		error = ENOMEM;
		goto done;
	}

	/*
	 * Cycle through the buffers, looking for data.
	 * If we've get through all the buffers with no data,
	 * break out of the loop.
	 */
	while (uio->uio_resid > 0) {
		int cpu_index = 0;
		int got_sample = 0;
		int error;

		/*
		 * Get one sample at a time from each queue.
		 * That includes the per-CPU queues, and the queue for non-running threads.
		 */
		for (cpu_index = 0;
		     cpu_index < kern_samples->s_ncpu;
		     cpu_index++) {
			kern_sample_set_t *cur_set = kern_samples->cpu_sample_sets[cpu_index];
			
			mtx_lock_spin(&cur_set->sample_spin);
			error = get_sample(cur_set, temp_sample, MIN(STAGING_BUFFER_SIZE, uio->uio_resid));
			mtx_unlock_spin(&cur_set->sample_spin);
			if (error == ENOENT) {
				// Empty, so not really an error.
				error = 0;
			} else if (error == 0) {
				size_t sample_size;

				sample_size = sizeof(kern_sample_t) + sizeof(caddr_t) * temp_sample->num_pcs;
				error = uiomove(temp_sample, sample_size, uio);
				if (error == 0)
					got_sample = 1;
			}
			if (error == ENOSPC) {
				// Not enough space to put into the buffer, so let's break out now
				// Note that this could cause the user-process to loop.
				error = 0;
				goto done;
			} else if (error != 0) {
#if SAMPLE_DEBUG
				uprintf("%s(%d):  error = %d\n", __FUNCTION__, __LINE__, error);
#endif
				goto done;
			}
			mtx_lock_spin(&cur_set->sample_spin);
			if (cur_set->sample_count > 1) {
				samples_left += cur_set->sample_count;
			}
			mtx_unlock_spin(&cur_set->sample_spin);
		}
#if SAMPLE_DEBUG > 1
		printf("%s(%d):  got_sample = %d, samples_left = %d\n", __FUNCTION__, __LINE__, got_sample, samples_left);
#endif
		if (got_sample == 0) {
			// We had no data and no errors
#if SAMPLE_DEBUG > 1
			printf("%s(%d):  No samples this round, ioflag = %#x, samples_left = %d\n", __FUNCTION__, __LINE__, ioflag, samples_left);
#endif
			break;
		}
	}
done:
	mtx_unlock(&sample_lock);
	if (uio->uio_resid == start // Means we had no samples read
	    && samples_left != 0 &&
	    ((ioflag & O_NONBLOCK) == 0)) {
		error = tsleep(&sample_data_ready, PCATCH, "kern.sample.read", 0);
		if (error == 0) {
#if SAMPLE_DEBUG > 1
			uprintf("%s(%d):  starting over\n", __FUNCTION__, __LINE__);
#endif
			goto start_over;
		}
	}
	if (temp_sample) {
//		uprintf("%s(%d)\n", __FUNCTION__, __LINE__);
		free(temp_sample, M_TEMP);
	}
	return error;
}

static int
sample_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	// Currently, no writing is allowed.
	return EPERM;
}

/*
 * Tell the device driver about us
 */
static void
sample_cdev_init(void *unused)
{
	// Create the device file
#if SAMPLE_DEBUG
	uprintf("%s(%d)\n", __FUNCTION__, __LINE__);
#endif
	sample_dev = make_dev(&sample_cdevsw, 0, UID_ROOT, GID_KMEM, 0600, SAMPLE_DEV_FILENAME);
}

static void
sample_init(void)
{
#if SAMPLE_DEBUG
	uprintf("%s\n", __FUNCTION__);
#endif
	KASSERT(sample_dev == NULL, ("sample device pointer is not null during module load"));
	sample_cdev_init(NULL);
	mtx_init(&sample_lock, "sample_lock", NULL, MTX_DEF);
}

static void
sample_unload(void)
{
	// Is this necessary?
#if SAMPLE_DEBUG
	uprintf("%s\n", __FUNCTION__);
#endif
	(void)mtx_trylock(&sample_lock);
	mtx_unlock(&sample_lock);
	mtx_destroy(&sample_lock);
	if (sample_dev) {
		destroy_dev(sample_dev);
		sample_dev = NULL;
	}
	release_sample_data();

	return;
}

/*
 * Thanks to http://www.rhyous.com/2011/11/08/how-to-write-a-freebsd-kernel-module/
 * for template.
 */
static int
EventHandler(struct module *inModule, int inEvent, void *inArg)
{
	int retval = 0;

	switch (inEvent) {
	case MOD_LOAD:
		sample_init();
		break;
	case MOD_UNLOAD:
		sample_unload();
		break;
	default:
		retval = EOPNOTSUPP;
	}

	return retval;
}

static moduledata_t moduleData = {
	"sample_driver_kmod",	// Module name
	EventHandler,		// Event handler
	NULL,			// Extra data
};

DECLARE_MODULE(sample_driver_kmod, moduleData, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

