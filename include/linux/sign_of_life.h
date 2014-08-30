/*
 * device_metrics.h
 *
 * Device metrics driver header file
 *
 * Copyright (C) Amazon Technologies Inc. All rights reserved.
 * Yang Liu (yangliu@lab126.com)
 * TODO: Add additional contributor's names.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Device Crash Reason */
#define DEV_CRASH_NO_CRASH                   0x00
#define DEV_CRASH_KERNEL_PANIC               0xaa
#define DEV_CRASH_WATCH_DOG                  0xab
#define DEV_CRASH_THERMAL_SHUTDOWN           0xac


/* Get the device crash reason */
u8 get_dev_crash_reason(void);

/* set the device as kernel panic crash */
void notify_dev_crash_kernel_panic(void);
