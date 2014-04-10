#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/systm.h>

#include "sample.h"

static struct cdev *sample_dev;
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

static int
sample_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return EBUSY;
}

static int
sample_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	return 0;
}

static int
sample_ioctl(struct cdev *dev,
	     u_long cmd,
	     caddr_t data,
	     int fflag,
	     struct thread *td)
{
	return 0;
}

static int
sample_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	return 0;
}

static int
sample_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	return 0;
}

/*
 * Tell the device driver about us
 */
static void
sample_cdev_init(void *unused)
{
	// Create the device file
	sample_dev = make_dev(&sample_cdevsw, 0, UID_ROOT, GID_KMEM, 0600, SAMPLE_DEV_FILENAME);
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
		sample_cdev_init(NULL);
		break;
	case MOD_UNLOAD:
		destroy_dev(sample_dev);
		sample_dev = NULL;
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

