
/**
 * TPLMS
 *
 * IMPORTANT: These definitions and structures must align with the those
 * in bionic/libc/kernel/common/linux/tplms.h. Normally, this file will be
 * processed by a script to automatically extract and generate linux/tplms.h,
 * but that may not be happening for this file.
 */


#ifndef _LINUX_TPLMS_H
#define _LINUX_TPLMS_H

#include <linux/types.h>
#include <linux/ioctl.h>


#ifdef __KERNEL__
long sys_tplms(int scenario, int tag, int extra1, int extra2);
#endif /* __KERNEL__ */

int tplms(int scenario, int tag, int extra1, int extra2);

#define TPLMS_DEFAULT_BUFFER_SIZE 13000         // (40 * 13000) = 520,000 bytes
#define TPLMS_PROC_NAME           "tplms"
#define TPLMS_DEV_NAME            "tplms"
#define NMETRICS_DEV_NAME         "nmetrics"

typedef struct {
	struct timespec tv;         // time stamp
	int sequence;               // assigned sequentially
	int scenario;               // scenario id
	int tag;                    // entry tag
	int extra1;                 // entry specific extra info
	int extra2;
	int pid;
	int tid;
	unsigned int cpu;
} tplms_entry_t;

typedef struct {
	tplms_entry_t entry;        // entry
	int overtaken;              // count of entries overtaken due to buffer wrap
	int remaining;              // count of remaining entries
	int total;                  // this many entries have been added since the last reset
} tplms_read_entry_t;

struct tplms_leds {
	unsigned int led1;
	unsigned int led2;
};

struct tplms_platform_data {
	struct tplms_leds *leds;
};

/* macros for splitting out fields
 */
#define TPLMS_LEVEL_OFFSET     30
#define TPLMS_FLAG_OFFSET      22
#define TPLMS_TRACE_ID_OFFSET   7
#define TPLMS_STRACE_ID_OFFSET  0

#define TPLMS_LEVEL_MASK        0xc0000000
#define TPLMS_FLAG_MASK         0x3fc00000
#define TPLMS_TRACE_ID_MASK     0x3fff80
#define TPLMS_STRACE_ID_MASK    0x7f

#define TPLMS_GET_LEVEL(x) ((x & TPLMS_LEVEL_MASK) >> TPLMS_LEVEL_OFFSET)
#define TPLMS_GET_FLAGS(x) ((x & TPLMS_FLAG_MASK) >> TPLMS_FLAG_OFFSET)
#define TPLMS_GET_TRACE_ID(x) ((x & TPLMS_TRACE_ID_MASK) >> TPLMS_TRACE_ID_OFFSET)
#define TPLMS_GET_STRACE_ID(x) ((x & TPLMS_STRACE_ID_MASK) >> TPLMS_STRACE_ID_OFFSET)

#define TPLMS_LEVEL(x) (x << TPLMS_LEVEL_OFFSET)
#define TPLMS_FLAGS(x) (x << TPLMS_FLAG_OFFSET)
#define TPLMS_TRACE_ID(x) (x << TPLMS_TRACE_ID_OFFSET)
#define TPLMS_STRACE_ID(x) (x << TPLMS_STRACE_ID_OFFSET)

#ifdef CONFIG_TPLMS
#define TPLMS(level, flags, cat, trace_id, strace_id, extra1, extra2)  \
  tplms(cat,                                                           \
        TPLMS_LEVEL(level) | TPLMS_FLAGS(flags) |                      \
        TPLMS_TRACE_ID(trace_id) | TPLMS_STRACE_ID(strace_id),         \
        extra1, extra2);
#else
#define TPLMS(level, flags, cat, trace_id, strace_id, extra1, extra2)
#endif

/* Category list (Note: The category field is a bitmap)
 */
#define TPLMS_CAT_CAM      0x00000001    // Camera
#define TPLMS_CAT_INPUT    0x00000002    // User Input / Sensors
#define TPLMS_CAT_POWER    0x00000004    // Power / sleep
#define TPLMS_CAT_SAPP     0x00000008    // Standard Android app
#define TPLMS_CAT_MISC     0x00000010    // Misc
#define TPLMS_CAT_DISP     0x00000020    // Display / graphics
#define TPLMS_CAT_TAPP     0x00000040    // Tyto specific app
#define TPLMS_CAT_EUCL     0x00000080    // Euclid
#define TPLMS_CAT_ALIFE    0x00000100    // Application lifecycle
#define TPLMS_CAT_GESTURE  0x00000200    // Gesture
#define TPLMS_CAT_MAPS     0x00000400    // Maps
#define TPLMS_CAT_ICEE     0x00000800    // ICEE
#define TPLMS_CAT_TCOMM    0x00001000    // TComm
#define TPLMS_CAT_AUDIO    0x00002000    // Audio
#define TPLMS_CAT_SEARCH   0x00008000    // Search experience
#define TPLMS_CAT_SPEECH   0x00010000    // Speech
#define TPLMS_CAT_PIM      0x00020000    // PIM - Contacts, Calendar, Email, Tasks
#define TPLMS_CAT_NMETRIC  0x80000000    // Native Metrics Adapter

/* Flags definitions
 */
#define TPFLAG_LED1U      0x1   // First debug LED on
#define TPFLAG_LED1D      0x2   // First debug LED off
#define TPFLAG_PERFSTART  0x4   // start perf tool
#define TPFLAG_PERFSTOP   0x8   // stop perf tool
#define TPFLAG_AL         0x10  // Copy to main Android log
#define TPFLAG_KL         0x20  // Copy to kernel log
#define TPFLAG_KT         0x40  // Copy to kernel trace
#define TPFLAG_LED2T      0x80  // Second debug LED toggle

/* Level definitions
 */
#define TP_HI     3
#define TP_MED    2
#define TP_LOW    1
#define TP_INFO   0

/* Quick TPLMS logs: Since most log entries don't set any flags and don't
 * use any extra data, these macros provide shortcuts to logging. The
 * resulting log entries are the same as the longer version.
 */

#define TPLMSH(cat, trace_id, strace_id) \
               TPLMS(TP_HI, 0, cat, trace_id, strace_id, 0, 0)
#define TPLMSM(cat, trace_id, strace_id) \
               TPLMS(TP_MED, 0, cat, trace_id, strace_id, 0, 0)
#define TPLMSL(cat, trace_id, strace_id) \
               TPLMS(TP_LOW, 0, cat, trace_id, strace_id, 0, 0)
#define TPLMSI(cat, trace_id, strace_id) \
               TPLMS(TP_INFO, 0, cat, trace_id, strace_id, 0, 0)

typedef struct {
	int bufferSize;         // the buffer will hold this many entries
	int count;              // the buffer contains this many entries
	int total;              // count of entries added since the last reset
	int overtaken;          // count of entries overtaken due to buffer wrap
} tplms_config;

#define __TPLMSIO	0xAF

#define TPLMS_GET_CONFIG         _IO(__TPLMSIO, 1) /* get configuration */
#define TPLMS_SET_BUFFER_SIZE    _IO(__TPLMSIO, 2) /* set log size */
#define TPLMS_SET_CAT_MASK       _IO(__TPLMSIO, 3) /* set category mask */
#define TPLMS_RESET_LOG_STORE    _IO(__TPLMSIO, 4) /* clear log */
#define TPLMS_GET_VERSION        _IO(__TPLMSIO, 5) /* get TPLMS version */
#define TPLMS_SET_LOG_LEVEL      _IO(__TPLMSIO, 6) /* set minimum log level */

#endif  /* _LINUX_TPLMS_H */
