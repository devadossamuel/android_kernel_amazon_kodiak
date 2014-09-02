/*
 * sign_of_life_msm.c
 *i
 * Device metrics driver on Qualcomm MSM platform
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
#include <linux/qpnp/power-on.h>


u8 get_dev_crash_reason(void)
{
   u8 crash_reason;

   qpnp_pon_read_xvdd_reg(&crash_reason);

   /* clean up the PMIC XVDD register for the crash signature */
   qpnp_pon_write_xvdd_reg(DEV_CRASH_NO_CRASH);
   printk(KERN_INFO "Sign of life: crash reason 0x%x", crash_reason);
   return crash_reason;
}
EXPORT_SYMBOL(get_dev_crash_reason);


void notify_dev_crash_kernel_panic(void)
{
   qpnp_pon_write_xvdd_reg(DEV_CRASH_KERNEL_PANIC);
}
EXPORT_SYMBOL(notify_dev_crash_kernel_panic);
