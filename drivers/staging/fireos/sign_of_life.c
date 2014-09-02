/*
 * sign_of_life.c
 *
 * Device Sign of Life information
 *
 * Copyright (C) Amazon Technologies Inc. All rights reserved.
 * Yang Liu (yangliu@lab126.com)
 * TODO: Add additional contributor's names.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <asm/uaccess.h>
#include <linux/sign_of_life.h>

#define DEV_SOL_VERSION     "0.1"
#define DEV_SOL_NAME        "sign_of_life"
#define DEV_BOOT_REASON     "dev_boot_reason"
#define DEV_CRASH_REASON    "dev_crash_reason"
#define MAX_SIZE             10

static const char * const dev_crash_reason[] = {
	[0] = "no crash",
	[1] = "kernel_panic",
	[2] = "watchdog",
	[3] = "thermal_shutdown",
};

struct dev_sol {
	u8   *data;
        u8   last_crash;
	struct mutex lock;
};
static struct dev_sol *p_dev_sol;

static int dev_crash_proc_read(char *page, char **start, off_t off, int count,
                                   int *eof, void *data)
{
	int len = 0;
	struct  dev_sol *psol = (struct dev_sol*)data;

	if (!psol)
		return -EINVAL;

	mutex_lock(&psol->lock);
	switch (psol->last_crash)  {
	case DEV_CRASH_KERNEL_PANIC:
		len = strlen(dev_crash_reason[1]) + 1;
		memcpy(page, dev_crash_reason[1], len);
		break;
	case DEV_CRASH_WATCH_DOG:
                len = strlen(dev_crash_reason[2]) + 1;
                memcpy(page, dev_crash_reason[2], len);
		break;
	case DEV_CRASH_THERMAL_SHUTDOWN:
                len = strlen(dev_crash_reason[3]) + 1;
                memcpy(page, dev_crash_reason[3], len);
		break;
	default:
                len = strlen(dev_crash_reason[0]) + 1;
                memcpy(page, dev_crash_reason[0], len);
		break;
	}

	mutex_unlock(&psol->lock);
	printk (KERN_INFO "%s: crash code 0x%x len %d %s\n", DEV_SOL_NAME, psol->last_crash, len, page);
	return len;
}


static int __init dev_sol_init(void)
{
	struct proc_dir_entry *entry;
	int status = 0;

	printk(KERN_ERR "Amazon: sign of life device driver init\n");
	p_dev_sol = kzalloc(sizeof(struct dev_sol), GFP_KERNEL);
	if (!p_dev_sol) {
		printk (KERN_INFO "%s: kmalloc allocation failed\n", DEV_SOL_NAME);
		status = -ENOMEM;
		goto init_out1;
	}
	mutex_init(&p_dev_sol->lock);

	entry = create_proc_entry(DEV_CRASH_REASON, S_IRUGO | S_IWUSR | S_IWGRP , NULL);
	if (!entry) {
		printk(KERN_ERR "%s: failed to create proc %s entry\n", DEV_SOL_NAME, DEV_CRASH_REASON);
		status = -ENOMEM;
		goto init_out;
	}

	p_dev_sol->last_crash = get_dev_crash_reason();
	entry->read_proc  = dev_crash_proc_read;
	entry->data = p_dev_sol;
	return 0;

init_out:
	remove_proc_entry(DEV_SOL_NAME, NULL);
init_out1:
	if (p_dev_sol)
		kfree(p_dev_sol);
	return status;
}

static void __exit dev_sol_cleanup(void)
{
	remove_proc_entry(DEV_CRASH_REASON, NULL);
	if (p_dev_sol)
		kfree(p_dev_sol);
}

late_initcall(dev_sol_init);
module_exit(dev_sol_cleanup);

MODULE_LICENSE("GPL v2");

