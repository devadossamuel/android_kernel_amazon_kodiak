/**
 *
 * Note: read entries from /proc/tplms
 *
 * TODO:
 * - replace all literal error return values with appropriate Linux error values
 * - pare down the included files - some are not necessary
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/bitops.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/proc_fs.h>
#include <linux/tplms.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/fcntl.h>
#include <linux/miscdevice.h>
// #include "logger.h" ACOS_ONELINE
#include <linux/debugfs.h>
#include <linux/completion.h>

#define CREATE_TRACE_POINTS
#include <trace/events/tplms_tp.h>

static const char g_tplms_version[] = "0.0";
static const char g_tplms_dev_name[] = TPLMS_DEV_NAME;
static const char g_nmetrics_dev_name[] = NMETRICS_DEV_NAME;

/**
 * Internal data structures
 */

static struct _tplms_device_info {
	struct miscdevice tplms_device;
	int blocked;
	wait_queue_head_t wq;
	int min_log_level;
	int cat_mask;
	int read_mask;
} tplms_device_info = {
	.tplms_device.name = g_tplms_dev_name,
	.read_mask = -1,
}, nmetric_device_info = {
	.tplms_device.name = g_nmetrics_dev_name,
	.read_mask = TPLMS_CAT_NMETRIC,
};

typedef struct {
	struct completion comp;
	int blocked;
} tplms_event_info;

static struct tplms_data {
	tplms_entry_t *pBuffer;         // base address of internal entry buffer
	tplms_entry_t *pLimit;          // first entry past the end of the buffer
	tplms_entry_t *pHead;           // entries are added at the head
	tplms_entry_t *pTail;           // entries are removed from the tail
	int bufferSize;                 // the buffer will hold this many entries
	int count;                      // the buffer contains this many entries
	int total;                      // count of entries added since reset
	int overtaken;                  // count of entries overtaken by wrapping
	struct proc_dir_entry *pProc;   // /proc node pointer
	spinlock_t bufLock;             // spin lock for SMP
} g_data = {
	.pBuffer = 0                    // ==0 indicates uninitialized
};

#ifdef CONFIG_TPLMS_LED
static unsigned int debug_led1, debug_led2;
#endif

static int tplms_retrieve_sequence(tplms_read_entry_t *pDst, int sequence);
static int tplms_control_reset(void);
static int tplms_proc_init(void);
static int tplms_device_init(struct _tplms_device_info *);

static int tplms_proc_write(struct file *pFile, const char __user *pBuff,
				unsigned long len, void *pData);
static void tplms_get_g_data(struct tplms_data *pData);
static int tplms_proc_read(char *pPage, char **ppStart, off_t off,
				int count, int *pEof, void *pData);
static int tplms_probe(struct platform_device *p);

static struct platform_driver tplms_platform = {
	.probe = tplms_probe,
	.driver = {
		.name = "tplms"
	}
};

#ifdef CONFIG_TPLMS_PERF
tplms_event_info tplms_trigger_start_perf, tplms_trigger_stop_perf;
static unsigned char tplms_perf_in_progress = 0;

static int tplms_debugfs_init(void);
static void tplms_init_event(tplms_event_info *event);
static void tplms_trigger_event(tplms_event_info *event);
static void tplms_wait_event(tplms_event_info *event);
#endif

static int tplms_open(struct inode *, struct file *);
static int tplms_release(struct inode *, struct file *);
static ssize_t tplms_read(struct file *, char *, size_t, loff_t *);
static ssize_t tplms_write(struct file *, const char *, size_t, loff_t *);
static loff_t tplms_llseek(struct file *filp, loff_t off, int whence);
static long tplms_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations fops = {
	 .llseek = tplms_llseek,
	 .read = tplms_read,
	 .write = tplms_write,
	 .open = tplms_open,
	 .release = tplms_release,
	 .unlocked_ioctl = tplms_ioctl,
};

//=============================================================================

/**
 * Kernel API used to log scenario points.
 */
SYSCALL_DEFINE4(tplms, int, scenario, int, tag, int, extra1, int, extra2)
{
	return tplms(scenario, tag, extra1, extra2);
}

static inline void tplms_handle_flags(int scenario, int tag)
{
#ifdef CONFIG_TPLMS_LED
	static char led2_state = 0;
#endif
	int flags = TPLMS_GET_FLAGS(tag);
	static unsigned char buf[27] = "\7TPLMS";

#ifdef CONFIG_TPLMS_LED
	if (flags & TPFLAG_LED1U)
		gpio_set_value(debug_led1, 1);
	if (flags & TPFLAG_LED1D)
		gpio_set_value(debug_led1, 0);
	if (flags & TPFLAG_LED2T) {
		led2_state ^= 0x1;
		gpio_set_value(debug_led2, led2_state);
	}
#endif
#ifdef CONFIG_TPLMS_PERF
	if (flags & TPFLAG_PERFSTART) {
		tplms_trigger_event(&tplms_trigger_start_perf);
	}
	if (flags & TPFLAG_PERFSTOP) {
		tplms_trigger_event(&tplms_trigger_stop_perf);
	}
#endif
	if (flags & TPFLAG_KL)
		printk(KERN_WARNING "TPLMS log: %08x\n", g_data.total);
	if (flags & TPFLAG_AL) {
		snprintf(&(buf[7]), 20, "Sequence = %08x", g_data.total);
//		__alog_main(buf, 27); // ACOS_ONELINE
	}
	if (flags & TPFLAG_KT)
		trace_tplms_tp(g_data.total);
}

/**
 * Internal kernel API used to log scenario points.
 */
int tplms(int category, int tag, int extra1, int extra2)
{
	unsigned long flags;
	tplms_entry_t *pEntry;
	struct timespec tv;
	int level;

	if (!g_data.pBuffer)
		return -98;

	if ((category & tplms_device_info.cat_mask) == 0)
		return 0;

	// Filter out events based on min_log_level
	if (tplms_device_info.min_log_level > 0) {
		level = ((unsigned)tag & TPLMS_LEVEL_MASK) >> TPLMS_LEVEL_OFFSET;
		if (level < tplms_device_info.min_log_level) {
			return 0;
		}
	}

	getnstimeofday(&tv);

	if (tag & TPLMS_FLAG_MASK)
		tplms_handle_flags(category, tag);

	spin_lock_irqsave(&g_data.bufLock, flags);
	if (g_data.count >= g_data.bufferSize) {
		g_data.pTail++;
		if (g_data.pTail >= g_data.pLimit)
			g_data.pTail = g_data.pBuffer;
		g_data.count--;
		g_data.overtaken++;
	}

	pEntry = g_data.pHead++;
	if (g_data.pHead >= g_data.pLimit)
		g_data.pHead = g_data.pBuffer;
	g_data.count++;

	pEntry->sequence = g_data.total++;

	pEntry->tv = tv;
	pEntry->scenario = category;
	pEntry->tag = tag;
	pEntry->extra1 = extra1;
	pEntry->extra2 = extra2;

#ifdef CONFIG_TPLMS_DETAIL
	pEntry->cpu = smp_processor_id();

	if (!in_interrupt()) {
		pEntry->pid = current->tgid;
		pEntry->tid = current->pid;
	}
	else {
		pEntry->pid = 0;
		pEntry->tid = 0;
	}
#else
	pEntry->cpu = 0;
	pEntry->pid = 0;
	pEntry->tid = 0;
#endif
	spin_unlock_irqrestore(&g_data.bufLock, flags);

	// unblock /dev/tplms
	if (tplms_device_info.blocked) {
		tplms_device_info.blocked = 0;
		wake_up_interruptible(&(tplms_device_info.wq));
	}

	// unblock /dev/nmetrics
	if (nmetric_device_info.blocked && (category & TPLMS_CAT_NMETRIC)) {
		nmetric_device_info.blocked = 0;
		wake_up_interruptible(&(nmetric_device_info.wq));
	}

	return 0;
}

/**
 * Retrieve a single entry by sequence. If the sequence is less than
 * current minimum sequence, the minimum sequence entry is returned
 * return value is also set to be sequence number of entry returned
 */
static int tplms_retrieve_sequence(tplms_read_entry_t *pDst, int sequence)
{
	int rc = -1;
	unsigned long flags;

	spin_lock_irqsave(&g_data.bufLock, flags);
	{
		int base = g_data.total - g_data.count;
		if (sequence < base)
			sequence = base;
		if (sequence < g_data.total) {
			int index = sequence - base;
			tplms_entry_t *pEntry = g_data.pTail + index;
			if (pEntry >= g_data.pLimit)
				pEntry -= g_data.bufferSize;
			pDst->entry = *pEntry;
			pDst->overtaken = g_data.overtaken;
			pDst->remaining = g_data.count - index - 1;
			pDst->total = g_data.total;
			rc = sequence;
		}
	}
	spin_unlock_irqrestore(&g_data.bufLock, flags);

	return rc;
}

/**
 * Reset the TPLMS store.
 */
static int tplms_control_reset(void)
{
	unsigned long flags;

	if (!g_data.pBuffer)
		return -1;

	spin_lock_irqsave(&g_data.bufLock, flags);
	g_data.total = g_data.count = g_data.overtaken = 0;
	g_data.pHead = g_data.pTail = g_data.pBuffer;
	spin_unlock_irqrestore(&g_data.bufLock, flags);
	return 0;
}

/**
 * Initialize the TPLMS /proc node.
 */
static int tplms_proc_init(void)
{
	if (g_data.pProc)
		return 0;

	g_data.pProc = create_proc_entry(TPLMS_PROC_NAME,
			S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP, NULL);

	if (!g_data.pProc) {
		printk(KERN_INFO "tplms_proc_init: cannot create /proc node\n");
		return -1;
	}

	g_data.pProc->read_proc = tplms_proc_read;
	g_data.pProc->write_proc = tplms_proc_write;
	return 0;
}

/**
 * Initialize a TPLMS device.
 */
static int tplms_device_init(struct _tplms_device_info *pDevice)
{
	int ret;

	pDevice->tplms_device.minor = MISC_DYNAMIC_MINOR;
	pDevice->tplms_device.fops = &fops;
	pDevice->tplms_device.parent = NULL;

	init_waitqueue_head(&pDevice->wq);
	pDevice->blocked = 0;
	pDevice->min_log_level = 0;
	pDevice->cat_mask = -1;

	ret = misc_register(&pDevice->tplms_device);
	if (ret)
		printk(KERN_ERR "tplms_init: cannot register misc device\n");

	return ret;
}

#ifdef CONFIG_TPLMS_PERF
static ssize_t tplms_dfs_char_read(struct file *file, char *buffer,
			size_t length, loff_t *offset)
{
	char buf[5] = {0};
	int size;
	tplms_event_info *event;

	event = (tplms_event_info *) file->private_data;
	if (event == NULL)
		return 0;

	size = snprintf(buf, sizeof(buf), "%u\n", event->blocked);
	if (size > 0)
		if (copy_to_user(buffer, buf, size))
			return 0;
	if (*offset == 0)
	{
		(*offset)++;
		return size;
	}
	else
	{
		return 0;
	}
}

static ssize_t tplms_dfs_char_write(struct file *file, const char *buffer,
			size_t length, loff_t *offset)
{
	char tmp;
	tplms_event_info *event;

	event = (tplms_event_info *) file->private_data;
	if (event == NULL)
		return 0;

	if (length == 0)
		return 0;
	get_user(tmp, buffer);
	if (tmp == '0') {
		if (event->blocked) {
			tplms_trigger_event(event);
		}
	} else {
		if (!event->blocked) {
			tplms_wait_event(event);
		}
	}
	return 1;
}

#define DEFINE_TPLMS_DEBUGFS_FILE_OPS(__event) \
static int __event ## _dfs_open(struct inode *inode, struct file * file) \
{ \
	file->private_data = &__event; \
	return nonseekable_open(inode, file); \
} \
static struct file_operations __event ## _fops = { \
	.open = __event ## _dfs_open, \
	.read = tplms_dfs_char_read, \
	.write = tplms_dfs_char_write, \
};

DEFINE_TPLMS_DEBUGFS_FILE_OPS(tplms_trigger_start_perf)
DEFINE_TPLMS_DEBUGFS_FILE_OPS(tplms_trigger_stop_perf)

static void tplms_init_event(tplms_event_info *event)
{
	event->blocked = 0;
	init_completion(&(event->comp));
}

static void tplms_trigger_event(tplms_event_info *event)
{
	if (event->blocked) {
		event->blocked = 0;
		complete_all(&(event->comp));
	}
}

static void tplms_wait_event(tplms_event_info *event)
{
	event->blocked = 1;
	INIT_COMPLETION(event->comp);
	wait_for_completion(&(event->comp));
}

/**
 * Initialize debugfs entries for tplms.
 */
static int tplms_debugfs_init(void)
{
	struct dentry *tplms_dfs_dir;
	// create the directory

	tplms_dfs_dir = debugfs_create_dir(TPLMS_DEV_NAME, NULL);
	if (tplms_dfs_dir == NULL)
	{
		printk(KERN_ERR "tplms_init: cannot create debug fs entry\n");
	}
	else
	{
		if (	(debugfs_create_file("perf_tool_wait_start", 0666,
				tplms_dfs_dir, NULL,
				&tplms_trigger_start_perf_fops) == NULL) ||
			(debugfs_create_file("perf_tool_wait_stop", 0666,
				tplms_dfs_dir, NULL,
				&tplms_trigger_stop_perf_fops) == NULL) ||
			(debugfs_create_u8("perf_tool_in_progress", 0666,
				tplms_dfs_dir,
				&tplms_perf_in_progress) == NULL)) {
			printk(KERN_ERR
				"tplms_init: cannot create debug fs entry\n");
		}
		else
		{
			tplms_init_event(&tplms_trigger_start_perf);
			tplms_init_event(&tplms_trigger_stop_perf);
		}
	}
	return 0;
}
#endif /* CONFIG_TPLMS_PERF */

/**
 * Responds to writes on any TPLMS /proc/tplms.
 * Currently does nothing.
 * It's thought that this could be a simple control interface.
 */
static int tplms_proc_write(struct file *pFile, const char __user *pBuff,
			unsigned long len, void *pData)
{

	if (!g_data.pBuffer)
		return -1;
	// do nothing
	return 0;
}

/**
 * Retrieve a snapshot of g_data.
 */
static void tplms_get_g_data(struct tplms_data *pData)
{
	unsigned long flags;

	spin_lock_irqsave(&g_data.bufLock, flags);
	*pData = g_data;
	spin_unlock_irqrestore(&g_data.bufLock, flags);
}

/**
 * Responds to reads on the TPLMS /proc/tplms.
 * Returns text block of TPLMS infrastructure info.
 * (See kernel/fs/proc/generic.c "How to be a proc read function")
 */
static int tplms_proc_read(char *pPage, char **ppStart, off_t off, int count,
			int *pEof, void *pData)
{
	struct tplms_data data;
	int rc;

	tplms_get_g_data(&data);

	*pEof = 1;
	rc = sprintf(pPage,	"TPLMS v0.0\n"
				"       size: %8d\n"
				"      count: %8d\n"
				"      total: %8d\n"
				"  overtaken: %8d\n",
		data.bufferSize, data.count, data.total, data.overtaken);

	return rc;
}

int tplms_probe(struct platform_device *p)
{
#ifdef CONFIG_TPLMS_LED
	debug_led1 = ((struct tplms_platform_data *)p->dev.platform_data)->leds->led1;
	debug_led2 = ((struct tplms_platform_data *)p->dev.platform_data)->leds->led2;
#endif
	return 0;
}

static int tplms_open(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	int minor = MINOR(inode->i_rdev);

	if (tplms_device_info.tplms_device.minor == minor)
		filp->private_data = (void*)&tplms_device_info;
	else if (nmetric_device_info.tplms_device.minor == minor)
		filp->private_data = (void*)&nmetric_device_info;
	else
		return -ENOENT;

	// set offset to be the current lowest sequence
	spin_lock_irqsave(&g_data.bufLock, flags);
	filp->f_pos = g_data.total - g_data.count;
	spin_unlock_irqrestore(&g_data.bufLock, flags);
	return 0;
}

static int tplms_release(struct inode *inode, struct file *file)
{
	return 0;
}

static loff_t tplms_llseek(struct file *filp, loff_t off, int whence)
{
	loff_t newpos;
	switch (whence) {
	case 0: /* SEEK_SET */
		newpos = off;
		break;

	case 1: /* SEEK_CUR */
		newpos = filp->f_pos + off;
		break;

	case 2: /* SEEK_END */
		newpos = g_data.total + off;
		break;

	default: /* can't happen */
		return -EINVAL;
	}
	if (newpos < 0) return -EINVAL;
	filp->f_pos = newpos;
	return newpos;
}

/*
 * reads out tplms entries from store
 */
static ssize_t tplms_read(struct file *filp, char *buffer, size_t length,
			loff_t *offset)
{
	struct _tplms_device_info * pDevice =
		(struct _tplms_device_info *)filp->private_data;
	tplms_read_entry_t entry;
	long ret;

	if (length < sizeof(entry))
		return 0;
	memset(&entry, 0, sizeof(entry));

	for (;;) {
		/*
		 * seq is the actual sequence number of entry being read, since
		 * it's possible the requested entry is already overtaken
		 */
		int seq = tplms_retrieve_sequence(&entry, (int)(*offset));
		if (seq != -1) {
			*offset = seq + 1;
			if (entry.entry.scenario & pDevice->read_mask) {
				/* copy this entry to the buffer */
				ret = copy_to_user(buffer, &entry, sizeof(entry));
				return (ssize_t)(sizeof(tplms_read_entry_t) - ret);
			}
		} else {
			if (filp->f_flags & O_NONBLOCK)
				return 0;
			pDevice->blocked = 1;
			if (wait_event_interruptible(pDevice->wq,
				pDevice->blocked == 0) == -ERESTARTSYS)
				return 0;
		}
	}
}

static ssize_t tplms_write(struct file *filp, const char *buffer,
			size_t length, loff_t *offset)
{
	// not allowing write for now
	return 0;
}

static long tplms_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct _tplms_device_info * pDevice =
		(struct _tplms_device_info *)filp->private_data;
	tplms_config config;
	struct tplms_data data;
	long rc = -1;
	unsigned long flags;

	switch (cmd) {
	case TPLMS_GET_CONFIG:
		tplms_get_g_data(&data);
		config.bufferSize = data.bufferSize;
		config.count = data.count;
		config.total = data.total;
		config.overtaken = data.overtaken;
		rc = copy_to_user((void __user *)arg, &config, sizeof(tplms_config));
		break;
	case TPLMS_SET_BUFFER_SIZE:
		break;
	case TPLMS_SET_CAT_MASK:
		pDevice->cat_mask = (int)arg;
		break;
	case TPLMS_RESET_LOG_STORE:
		rc = tplms_control_reset();
		break;
	case TPLMS_GET_VERSION:
		// copy entire string with terminating null
		rc = copy_to_user((void __user *)arg, g_tplms_version,
				sizeof(g_tplms_version));
		break;
	case TPLMS_SET_LOG_LEVEL:
		// set offset to be the current lowest sequence
		spin_lock_irqsave(&g_data.bufLock, flags);
		pDevice->min_log_level = arg;
		spin_unlock_irqrestore(&g_data.bufLock, flags);
		rc = 0;
		break;
	default:
		break;
	}
	return rc;
}

static int __init tplms_init(void)
{
	if (g_data.pBuffer)
		return 0;

	g_data.bufferSize = TPLMS_DEFAULT_BUFFER_SIZE;
	g_data.total = g_data.count = g_data.overtaken = 0;
	g_data.pProc = 0;
	spin_lock_init(&g_data.bufLock);
	g_data.pLimit = g_data.pHead = g_data.pTail = g_data.pBuffer =
		(tplms_entry_t *)kmalloc(
			sizeof(tplms_entry_t) * g_data.bufferSize, GFP_KERNEL);
	g_data.pLimit += g_data.bufferSize;
	if (!g_data.pBuffer) {
		printk(KERN_INFO "tplms_init: cannot allocate kernel memory\n");
		return -ENOMEM;
	} else {
		tplms_proc_init();

		tplms_device_init(&tplms_device_info);
		tplms_device_init(&nmetric_device_info);

#ifdef CONFIG_TPLMS_PERF
		tplms_debugfs_init();
#endif
		platform_driver_register(&tplms_platform);
	}
	return 0;
}

__initcall(tplms_init);

