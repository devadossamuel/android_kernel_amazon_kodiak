/*
 * wakeup_monitor.c - PM wakeup minitor functionality
 *
 * Copyright (c) 2013 Lab126
 *
 */

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rtc.h>
#include <linux/workqueue.h>
#include <linux/syscore_ops.h>
#include "linux/wm.h"

#define FILE_MODE 644
#define BUFFER_LEN 8
#define EVENT_STR_LEN 32
#define SEP_STR "!w!"
#define WIFI_EVENT_HEADER "WIFI_WAKUP="
#define MODEM_EVENT_HEADER "MODEM_WAKEUP="
struct proc_dir_entry *wm_proc_entry=NULL;
static char control_buff[BUFFER_LEN];


#define PWR_BUTTON_IRQ 291
#define WCNSS_TX 177
#define WCNSS_RX 178
#define SMD_MODEM 57
#define RTC_ALARM 325
#define RPM_IRQ 200
#define DEFAULT_CONTROL "disable\0"


static int enabled=0;  	/* default is disabled */
static int wakeup_detected = 0; /* default is not detect */
static struct work_struct wakeup_defer_work;

enum irq_num {
	IRQ_UNKNOWN=0,
	IRQ_WCNSS_RX,
	IRQ_MODEM,
	IRQ_RTC_ALARM,
        IRQ_TYPES,
};

#define MAX_PROCESS_NAME 64
#define MAX_PID_PRINT 3
struct wakeup_process {
	char name[MAX_PROCESS_NAME];
	pid_t pid;
	pid_t uid;
	unsigned long count;
	struct list_head list;
};

static LIST_HEAD(wifi_wakeup_processes_list);
static LIST_HEAD(alarm_wakeup_processes_list);

//static enum irq_num last_triggered_irq = IRQ_UNKNOWN;
static unsigned long wakeup_counts[IRQ_TYPES];
static unsigned long wakeup_uevent_trigger_counts[IRQ_TYPES];
//static int wakeup_count_increment=0;
static enum irq_num wakeup_count_update_item=IRQ_UNKNOWN;
static struct kobject *wm_root = NULL;
static struct kobject *wm_kobj = NULL;
static struct kset *wm_kset = NULL;
static u32 last_vmin_count = 0;
static int print_pid = 0;

static struct wakeup_source wakeup_monitor_ws;

#define DEFINE_OPEN_FUNC(name) proc_##name##_open


#define DEFINE_FILE_OPERATIONS(name)                                    \
                                                                        \
        struct file_operations wakeup_proc_##name##_fops = {            \
                .open = DEFINE_OPEN_FUNC(name),                         \
                .read = seq_read,                                       \
                .llseek = seq_lseek,                                    \
                .release = single_release,                              \
}

#define DEFINE_PROC_OPEN(name)                                          \
                                                                        \
        int proc_##name##_open(struct inode *inode, struct file *filp) { \
                return single_open(filp, show_##name, NULL);            \
        }
  
static int wakeup_process_alloc_and_add(struct list_head *head,
					const char *name, 
					const pid_t pid, 
					const pid_t uid)
{
	struct wakeup_process *wk = kzalloc(sizeof(struct wakeup_process), GFP_KERNEL);

	if (!wk){
		pr_err("%s: Error failed to allocate memory for wakeup_process\n", __func__);
		return -ENOMEM;
	}

	strncpy(wk->name, name, MAX_PROCESS_NAME - 1);
	wk->pid = pid;
	wk->uid = uid;
	wk->count = 1;
	INIT_LIST_HEAD(&wk->list);
	list_add(&wk->list, head);

	return 0;
}

static void wakeup_process_show(struct seq_file *m, struct list_head *head)
{
	struct wakeup_process *wk;
	list_for_each_entry(wk, head, list) {
		seq_printf(m, "%s:%lu\n", wk->name, wk->count);
	}
}
		

static int wakeup_process_find_and_increment(struct list_head *head, const int uid)
{
	struct wakeup_process *wk;
	list_for_each_entry(wk, head, list) {
		if (wk->uid == uid){
			pr_debug("%s: found the process=%s with uid=%d, count=%lu\n",
				 __func__, wk->name, uid, wk->count);
			wk->count++;
			return 1;
		}
	}
	return 0;
}

#if defined(WAKEUP_MONITOR_CHECK_KOBJ)
static void check_kobj(void)
{
	struct kobject *top_kobj;
        const char *devpath = NULL;

        top_kobj = wm_kobj;
        while(!top_kobj->kset && top_kobj->parent)
                top_kobj = top_kobj->parent;
        if (!top_kobj->kset){
                pr_err("%s: ERROR '%s' (%p): attempted to send uevent "
                       "without kset!\n", __func__, kobject_name(wm_kobj), wm_kobj);
        }else {
                pr_info("%s: top_kobj is not null. %s attempt to send uevent\n",
                        __func__, kobject_name(wm_kobj));
                
                devpath = kobject_get_path(wm_kobj, GFP_KERNEL); 
                if (!devpath){
                        pr_err("%s: devpath is not allocated.\n", __func__);
                }else {
                        pr_info("%s: subsystem = %s, dev_path = %s\n",
                                __func__, kobject_name(&wm_kset->kobj),
                                devpath);
                        kfree(devpath);
                }
                
        }
}
#endif

#if defined (WAKEUP_MONITOR_PRINT_TIMER)
static void print_timer(void)
{
	struct timespec ts;
//	struct rtc_time tm;
	getnstimeofday(&ts);
	
	if (!first_wakeup){
		struct timespec diff = timespec_sub(ts, last_wakeup_time);
		pr_info("%s: rtc time diff %lu(sec) and %lu(nsec)\n",
			__func__, diff.tv_sec, diff.tv_nsec);
	}else {
		/* first wakeup */
		first_wakeup = 0;
                //check_kobj();
	}

	last_wakeup_time.tv_sec = ts.tv_sec;
	last_wakeup_time.tv_nsec = ts.tv_nsec;

#if 0
	rtc_time_to_tm(ts.tv_sec, &tm);
	pr_info(" %d-%02d-%02d %02d:%02d:%02d.%09lu UTC\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
#endif
}

#endif

static ssize_t control_write(struct file *file, const char __user *buffer,
			size_t len, loff_t *pos)
{
	/* len -1 to assure the null-terminator character */
	ssize_t cp_len = len > (BUFFER_LEN-1) ? (BUFFER_LEN-1) : len;
        // buffer will also include the space is "echo enable > " with space and 
        // the len is 7
	memset (control_buff, 0, BUFFER_LEN);
	if (copy_from_user(control_buff, buffer, cp_len)){
		return -EFAULT;
	}
	
	/* hardcode the size to remove the extra space */
	if (strncmp(control_buff, "enable", 6) == 0){
		pr_debug("%s: enabling the wakeup monitor\n", __func__);
		enabled = 1;
	}else {
		pr_debug("%s: disable the wakeup monitor\n", __func__);
		enabled = 0;
	}
	return cp_len;
}

//static int wm_read_proc(char *page, char **start,
//		off_t off,int count, int *eof, void *data)
static int show_control(struct seq_file *m, void *v)
{
	int len = strlen(control_buff);
        if (len <= 0) {
                pr_err("%s: ERROR control_buff string is invalid\n", __func__);
                return -EBUSY;
        }

        seq_printf(m, "%s\n", control_buff);
	return 0;
}

/* 
   locking is not necessary since the scan_wakeup_irq is invoked with local irq disabled.
   do we need spin lock? do we care race condition?
 */
static int show_wifi(struct seq_file *m, void *v)
{
        seq_printf(m, "%lu\t%lu\n", wakeup_counts[IRQ_WCNSS_RX],
		wakeup_uevent_trigger_counts[IRQ_WCNSS_RX]);

	wakeup_process_show(m, &wifi_wakeup_processes_list);
        return 0;
}
static int show_alarm(struct seq_file *m, void *v)
{
        seq_printf(m, "%lu\t%lu\n", wakeup_counts[IRQ_RTC_ALARM], 
		   wakeup_uevent_trigger_counts[IRQ_RTC_ALARM]);
	wakeup_process_show(m, &alarm_wakeup_processes_list);
        return 0;
}
static int show_modem(struct seq_file *m, void *v)
{
        seq_printf(m, "%lu\t%lu\n", wakeup_counts[IRQ_MODEM],
		   wakeup_uevent_trigger_counts[IRQ_MODEM]);
        return 0;
}

#ifdef CONFIG_WAKEUP_MONITOR_UEVENT
static int trigger_uevent(char *str)
{
        char *envp[2];
        int ret  = 0;
        if (!str){
                pr_err("%s: Error invalid pointer.\n", __func__);
                return 1;
        }

        envp[0] = str;
        envp[1] = NULL;

        pr_debug("%s: sending uevent: %s\n", __func__, str);
        ret  = kobject_uevent_env(wm_kobj, KOBJ_CHANGE, envp);
        if (ret){
                pr_err("%s: Error failed to send uevent: %s\n", __func__, str);
        }

        return ret;
}
#else
#define trigger_uevent(a)
#endif

extern int msm_rpmstats_read(u32 *);

static int is_wakeup_from_vmin(void)
{
	u32 vmin_count=0;   /* tracking the last vmin counter */
	pr_debug("%s: Enter(cpu=%u, pid=%d)\n", __func__, smp_processor_id(), current->pid);
        /* every wakeup read the count */
        if (msm_rpmstats_read(&vmin_count) == 0){
                if (vmin_count > last_vmin_count){
                        pr_info("%s: wakeup from vmin\n",  __func__);
                        last_vmin_count = vmin_count;
			return 1;
		}
	}
	return 0;
}

/*  
    Notes:
    we possibly can't send uevent to user space in the syscore_ops function 
    since the userspace already frozen. so we do it in the defered function

    it is possible that we are in the middle of the function, the autosleep
    thread start again. maybe take a wake lock and release it.

    There is possible race that when we update the trigger count, the
    userspace process is reading the alarm count, but it is ok, since the 
    userspace is just reading the count, it does not really matter the count 
    is getting updated while in the middle of reading.

    another race condition is that the system enter suspend again in the middle 
    __pm_stay_awake() function, which is ok, we allow the system enter suspend \
    before we update the trigger counts and sending the uevent, we just missed 
    one count, not bit deal. Since it is likely that the system enter suspend 
    event before the wakeup_defer_func() get chance (scheduled) to run.
 */
static void wakeup_defer_func(struct work_struct *work)
{
	__pm_stay_awake(&wakeup_monitor_ws);  // hold a wake lock just to make sure we send the uevent
	if (wakeup_count_update_item == IRQ_RTC_ALARM){
		wakeup_uevent_trigger_counts[IRQ_RTC_ALARM]++;

		trigger_uevent("ALARM_WAKEUP=TRIGGERED");
		pr_debug("%s: cur_pid=%d,tgid=%d,g_pid=%d,g_tgid=%d,cur=%s,g_cur=%s, uid=%d\n",
			 __func__, current->pid, current->tgid, 
			 current->group_leader->pid,
			 current->group_leader->tgid, 
			 current->comm,
			 current->group_leader->comm,
			 current_uid());
		if (!wakeup_process_find_and_increment(&alarm_wakeup_processes_list, current_uid())){
			/* did not find the process, alloc a new one and add it */
			wakeup_process_alloc_and_add(&alarm_wakeup_processes_list, current->group_leader->comm,
						     current->pid, current_uid());
		}
	}
	is_wakeup_from_vmin();
	__pm_relax(&wakeup_monitor_ws);
}

void scan_wakeup_irq(unsigned int irq_num)
{
	if (enabled){
		switch(irq_num){
		case WCNSS_RX:
			pr_debug("%s: wifi interrupt triggered\n", __func__);
			wakeup_detected = 1;
                        wakeup_count_update_item=IRQ_WCNSS_RX;
			wakeup_counts[wakeup_count_update_item]++;
			print_pid=MAX_PID_PRINT;
			schedule_work(&wakeup_defer_work);
			break;
		case RTC_ALARM:
			pr_debug("%s: alarm interrupt triggered\n", __func__);
			wakeup_count_update_item = IRQ_RTC_ALARM;
			wakeup_detected = 0; /* clear the flag just incase alarm irq followed by wifi  */
			wakeup_counts[wakeup_count_update_item]++;
			schedule_work(&wakeup_defer_work);
			break;
		case SMD_MODEM:
			pr_debug("%s: modem interrupt triggered\n", __func__);
			wakeup_detected = 1;
			wakeup_count_update_item = IRQ_MODEM;
			wakeup_counts[wakeup_count_update_item]++;
			print_pid=MAX_PID_PRINT;
			schedule_work(&wakeup_defer_work);
			break;
		}

	}
}

EXPORT_SYMBOL(scan_wakeup_irq);

void reset_wakeup_detected(void)
{
	if (print_pid > 0){
		pr_info("%s: cur_pid = %d, %s, %s\n", __func__,
		       current->pid, current->comm, current->group_leader->comm);
		print_pid--;
	}
	wakeup_detected = 0;
}

EXPORT_SYMBOL(reset_wakeup_detected);

void check_wakeup(void)
{
	char str[EVENT_STR_LEN];
	
	if (print_pid > 0) {
		pr_info("%s: Enter, cur_pid = %d, %s, %s\n", __func__, 
			current->pid, current->comm, current->group_leader->comm);
		print_pid--;
	}

	if (wakeup_detected){
		/* remote wakeup is detected */
		pr_info("%s: WIFI Wakeup: process id: %d, group leader pid: %d,"			\
		       "process name: %s, grounp leader/Application name: %s\n",
		       __func__, current->pid, current->tgid, 
		       current->comm, current->group_leader->comm);

		if (wakeup_count_update_item == IRQ_WCNSS_RX){
			snprintf(str, EVENT_STR_LEN - 1, "%s%s%s%d", WIFI_EVENT_HEADER, 
				 current->group_leader->comm, SEP_STR, current_uid());
			pr_debug("%s: wifi uevent triggered\n",__func__);
			wakeup_uevent_trigger_counts[IRQ_WCNSS_RX]++;
			
			if (!wakeup_process_find_and_increment(&wifi_wakeup_processes_list, current_uid())){
				/* did not find the process, alloc a new one and add it */
				wakeup_process_alloc_and_add(&wifi_wakeup_processes_list, current->group_leader->comm,
							     current->pid, current_uid());
			}
			trigger_uevent(str);
		}else if (wakeup_count_update_item == IRQ_MODEM){
			snprintf(str, EVENT_STR_LEN - 1, "%s%s%s%d", 
				 MODEM_EVENT_HEADER, 
				 current->group_leader->comm, SEP_STR, current_uid());
			pr_debug("%s: modem uevent triggered\n", __func__);
			wakeup_uevent_trigger_counts[IRQ_MODEM]++;
			trigger_uevent(str);
		}
		/* clear the flag */
		reset_wakeup_detected();
		wakeup_count_update_item=IRQ_UNKNOWN;
	}

}
EXPORT_SYMBOL(check_wakeup);

static unsigned long flag = 1;
static ssize_t wm_show(struct kobject *kobj, 
		       struct attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", flag);
}

/*
static ssize_t wm_store(struct kobject *kobj,
                                  struct kobj_attribute *attr,
                                  const char *buf, size_t n)
{

	return 0;
}
*/

static struct proc_dir_entry *proc_wakeup_monitor_dir = NULL;

static DEFINE_PROC_OPEN(control)
static DEFINE_PROC_OPEN(wifi)
static DEFINE_PROC_OPEN(alarm)
static DEFINE_PROC_OPEN(modem)

static const DEFINE_FILE_OPERATIONS(modem);
static const DEFINE_FILE_OPERATIONS(wifi);
static const DEFINE_FILE_OPERATIONS(alarm);


static const struct file_operations wakeup_proc_control_fops = {
        .open = proc_control_open,
        .read = seq_read,
        .write = control_write,
        .llseek = seq_lseek,
        .release = single_release,
};


static struct attribute wm_attr = {
	.name = "wm",
	.mode = 0777,
};

static const struct sysfs_ops wm_ops = {
	.show = wm_show,
	.store = NULL,
};

static struct kobj_type wm_ktype = {
	.sysfs_ops = &wm_ops,
};

static int wakeup_monitor_suspend(void)
{
	pr_debug("%s: Enter\n", __func__);
	wakeup_detected = 0;
	wakeup_count_update_item=IRQ_UNKNOWN;
	print_pid = 0;
	return 0;
}
/*
static void wakeup_monitor_resume(void)
{
	wm_resumed_count++;
	pr_debug("%s: resume count = %lu\n", __func__, wm_resumed_count);
}
*/
/*
static int wm_suspend_notifier(struct notifier_block *nb, unsigned long event,
			       void *dummy)
{
	
}
*/
static struct syscore_ops wakeup_monitor_ops = {
	.suspend = wakeup_monitor_suspend,
//	.resume = wakeup_monitor_resume,
};

/*
static struct notifier_block wakeup_monitor_pm_notifier = {
	.notifier_call = wm_suspend_notifier,
};
*/

static int wakeup_monitor_create_uevent_entry(struct kobject *parent)
{
	int err;

	/* instantiate a kset object */
	wm_kset = kset_create_and_add("wm_kset", NULL, parent);
	if (!wm_kset){
		pr_err("%s: Error failed to create wm_kset object\n", 
		       __func__);
		return -ENOMEM;
	}
	wm_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!wm_kobj){
		pr_err("%s: Error failed to create wm_kobj object\n",
		       __func__);
		goto fail1;
	}

	wm_kobj->kset = wm_kset;
	err = kobject_init_and_add(wm_kobj, &wm_ktype, NULL, "wm_uevent");
	if (err){
		pr_err("%s: ERROR failed to create 'wm_uevent' object\n",
		       __func__);
		goto fail2;
	}

	err = sysfs_create_file(wm_kobj, &wm_attr);
	
	if (err){
		pr_err("%s: Error failed to create attributes\n", __func__);
		goto fail2;
	}

	return 0;

fail2: kobject_del(wm_kobj);
fail1: kset_unregister(wm_kset);
	return -ENOMEM;
}

//int init_wakeup_monitor(struct kobject *parent)
static int __init wakeup_monitor_init(void)
{
	int err;
	struct proc_dir_entry *entry;
	memset(control_buff, 0, sizeof(BUFFER_LEN));

	strncpy(control_buff, DEFAULT_CONTROL, strlen(DEFAULT_CONTROL));

	// create node /sys/wakeup_monitor
	wm_root = kobject_create_and_add("wakeup_monitor", NULL);

	if (!wm_root) {
		pr_err("%s: Error failed to create wm_root object\n",
		       __func__);
		return -ENOMEM;
	}

        proc_wakeup_monitor_dir = proc_mkdir("wakeup_monitor", NULL);
        if (!proc_wakeup_monitor_dir){
                pr_err("%s: ERROR failed to mkdir wakeup_monitor dir\n", __func__);
                return -ENOMEM;
        }

        entry = proc_create("control", 0, proc_wakeup_monitor_dir, 
			    &wakeup_proc_control_fops);
        if (!entry) {
                pr_err("%s: Error failed to create control entry\n", __func__);
                goto fail1;
        }

        entry  = proc_create("modem_count", 0, proc_wakeup_monitor_dir, 
			     &wakeup_proc_modem_fops);
        if (!entry) {
                pr_err("%s: Error failed to create modem entry\n",__func__);
                goto fail2;
        }

        proc_create("wifi_count", 0, proc_wakeup_monitor_dir, 
		    &wakeup_proc_wifi_fops);

        if (!entry) {
                pr_err("%s: Error failed to create wifi entry\n",__func__);
                goto fail3;
        }

        proc_create("alarm_count", 0, proc_wakeup_monitor_dir, 
		    &wakeup_proc_alarm_fops);
        if (!entry) {
                pr_err("%s: Error failed to create alarm entry\n",__func__);
                goto fail4;
        }

        INIT_WORK(&wakeup_defer_work, wakeup_defer_func);

	wakeup_source_init(&wakeup_monitor_ws, "wakeup_monitor");

	err = wakeup_monitor_create_uevent_entry(wm_root);

	if (err) goto fail5;

	register_syscore_ops(&wakeup_monitor_ops);

        return 0;

 fail5: remove_proc_entry("alarm_count", proc_wakeup_monitor_dir);
 fail4: remove_proc_entry("wifi_count", proc_wakeup_monitor_dir);
 fail3: remove_proc_entry("modem_count", proc_wakeup_monitor_dir);
 fail2: remove_proc_entry("control", proc_wakeup_monitor_dir);
 fail1: remove_proc_entry("wakeup_monitor", NULL);

	kobject_del(wm_root);

	return -ENOMEM;
}

module_init(wakeup_monitor_init);

static void wakeup_monitor_exit(void)
{

	sysfs_remove_file(wm_kobj, &wm_attr);
	kset_unregister(wm_kset);
	kobject_del(wm_kobj);
	kobject_del(wm_root);

	remove_proc_entry("alarm_count", proc_wakeup_monitor_dir);
	remove_proc_entry("wifi_count", proc_wakeup_monitor_dir);
	remove_proc_entry("modem_count", proc_wakeup_monitor_dir);
	remove_proc_entry("control", proc_wakeup_monitor_dir);
	remove_proc_entry("wakeup_monitor", NULL);
}
module_exit(wakeup_monitor_exit);
//MODULE_LICENSE("GPL");
