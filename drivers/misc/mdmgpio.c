/*
 * mdmgpio.c  --  Modem GPIO driver
 *
 * Copyright 2013 Lab126/Amazon, Inc.  All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/io.h>
#include <linux/gpio.h>
#include <linux/kobject.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/wakelock.h>
#include <linux/miscdevice.h>

#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/of_device.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/driver.h>
#include <mach/gpiomux.h>
#include <mach/subsystem_restart.h>


#define INTERRUPT_DEBOUNCE_TIME		30

#define GPIO_INVALID			-1

/* GPIO PINs related to modem */
#define MDMGPIO_SIM_DETECT      100

static int gpio_wan_sim_present = GPIO_INVALID;
static int mdmgpio_sim_present_status = -1;
static int mdmgpio_sim_present_invert;

static struct kobject *mdmgpio_kobj;
static struct kset *mdmgpio_kset;

#define mdmgpio_interrupt_handler(intr_name, work_queue)		\
do {								\
	disable_irq_nosync(gpio_to_irq(gpio_wan_##intr_name));	\
	schedule_delayed_work(&mdmgpio_##work_queue,		\
		msecs_to_jiffies(INTERRUPT_DEBOUNCE_TIME));	\
} while (0)

static int mdmgpio_request_gpio(void)
{
	return gpio_request(gpio_wan_sim_present, "Sim_Present");
}

void mdmgpio_free_gpio(void)
{
	gpio_free(gpio_wan_sim_present);
	return;
}


static ssize_t mdmgpio_sim_present_show(struct kobject *kobj,
			struct kobj_attribute *attr,
			char *buf)
{
	if (strcmp(attr->attr.name, "sim_present"))
		return -ENOENT;

	return snprintf(buf, PAGE_SIZE, "%d", mdmgpio_sim_present_status);
}

static ssize_t mdmgpio_sim_invert_show(struct kobject *kobj,
			struct kobj_attribute *attr,
			char *buf)
{
	if (strcmp(attr->attr.name, "sim_invert"))
		return -ENOENT;

	return snprintf(buf, PAGE_SIZE, "%d", mdmgpio_sim_present_invert);
}

static ssize_t mdmgpio_sim_invert_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf,
				size_t count)
{
	int var;
	sscanf(buf, "%du", &var);

	if (strcmp(attr->attr.name, "sim_invert"))
		return -ENOENT;

	switch (var) {
	case 1:
	case 0:
		mdmgpio_sim_present_invert = var;
		if (mdmgpio_sim_present_invert)
			mdmgpio_sim_present_status = \
				!mdmgpio_sim_present_status;
	default:
		printk(KERN_WARNING "Invalid input\n");
	}

	return count;
}

static ssize_t mdmgpio_restart_modem_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf,
				size_t count)
{
	int var, ret;
	sscanf(buf, "%du", &var);

	if (strcmp(attr->attr.name, "restart_modem"))
		return -ENOENT;

	switch (var) {
	case 1:
		printk(KERN_INFO "Restart modem...\n");
		ret = subsystem_restart_only("modem");
		if (ret != 0) {
			printk(KERN_WARNING "Failed to restart modem\n");
			return ret;
		}
		break;
	default:
		printk(KERN_WARNING "Invalid input!\n");
		return -EINVAL;
	}

	return count;
}

/*
 * Expose attributes - SIM detection as regular files
 */
static struct kobj_attribute mdmgpio_sim_present_attribute =
	__ATTR(sim_present, 0444, mdmgpio_sim_present_show, NULL);

static struct kobj_attribute mdmgpio_sim_invert_attribute =
	__ATTR(sim_invert, 0644, mdmgpio_sim_invert_show, \
		mdmgpio_sim_invert_store);

static struct kobj_attribute mdmgpio_restart_modem_attribute =
	__ATTR(restart_modem, 0644, NULL, \
		mdmgpio_restart_modem_store);

static struct attribute *attrs[] = {
	&mdmgpio_sim_present_attribute.attr,
	&mdmgpio_sim_invert_attribute.attr,
	&mdmgpio_restart_modem_attribute.attr,
	NULL,
};

/*
 * Create an attribute group with no attribute name (an attribute name
 * would be taken as a subdirectory)
 */
static struct attribute_group attr_group = {
	.name = NULL,
	.attrs = attrs,
};

/*
 * We get here if we receive an interrupt. This could be
 * on a rising or falling edge.
 */
static void mdmgpio_sim_present(struct work_struct *dummy)
{
	char *envp[] = { NULL, NULL};
	int sim_gpio_v = gpio_get_value(gpio_wan_sim_present);

	if (mdmgpio_sim_present_invert)
		sim_gpio_v = !sim_gpio_v;
	if (mdmgpio_sim_present_status ==
		sim_gpio_v) {

		/* Spurious interrupt */
		enable_irq(gpio_to_irq(gpio_wan_sim_present));
		return;
	}

	/* Should have been initialized to 0 during power up*/
	if (mdmgpio_sim_present_status == -1) {
		enable_irq(gpio_to_irq(gpio_wan_sim_present));
		return;
	}

	mdmgpio_sim_present_status = sim_gpio_v;

	enable_irq(gpio_to_irq(gpio_wan_sim_present));

	/*
	 * Right now, we send uevent about the SIM.
	 */
	mdmgpio_sim_present_status ? (envp[0] = "SIM_PRESENT=1") :
			(envp[0] = "SIM_PRESENT=0");
	kobject_uevent_env(mdmgpio_kobj, KOBJ_CHANGE, envp);

	return;
}

static DECLARE_DELAYED_WORK(mdmgpio_sim_present_work, mdmgpio_sim_present);

static irqreturn_t mdmgpio_sim_present_handler(int irq, void *devid)
{
	mdmgpio_interrupt_handler(sim_present, sim_present_work);
	return IRQ_HANDLED;
}

static int mdmgpio_gpio_init(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;

	gpio_wan_sim_present = of_get_gpio(np, 0);
	if ((gpio_wan_sim_present == GPIO_INVALID)) {
		printk(KERN_ERR "WAN gpio's not initialized.\n");
		return -EINVAL;
	}

	return mdmgpio_request_gpio();
}

static void mdmgpio_gpio_deinit(void)
{
	mdmgpio_free_gpio();
}

static int __devinit mdmgpio_probe(struct platform_device *pdev)
{
	int retval, irq;

	printk(KERN_INFO "%s\n", __func__);
	retval = mdmgpio_gpio_init(pdev);
	if (retval)
		return retval;

	/*
	 * create a "wan" directory in sysfs.
	 * The first argument specifies the name of the kernel object
	 * (and hence the directory) to be created. The second argument
	 * specifies the kernel object associated with the parent directory.
	 */
	mdmgpio_kobj = kobject_create_and_add("wan", NULL);

	if (!mdmgpio_kobj) {
		printk(KERN_ERR "Failed to create wan object\n");
		return -ENOMEM;
	}

	/*
	 * this would create the attribute group with the files as the
	 * attributes - power, usb_en, fw_rdy.
	 */
	retval = sysfs_create_group(mdmgpio_kobj, &attr_group);

	if (retval) {
		printk(KERN_ERR "Failed to create wan attributes\n");
		goto error;
	}

	mdmgpio_kset = kset_create_and_add("mdmgpio_kset", NULL, NULL);

	if (!mdmgpio_kset) {
		retval = -1;
		goto error;
	}

	mdmgpio_kobj->kset = mdmgpio_kset;

	/*
	 * initialize sim present gpio
	 */
	if (gpio_direction_input(gpio_wan_sim_present)) {
		retval = -1;
		goto error;
	}

	mdmgpio_sim_present_status = gpio_get_value(gpio_wan_sim_present);
	if (mdmgpio_sim_present_invert)
		mdmgpio_sim_present_status = !mdmgpio_sim_present_status;

	/*
	 * request an irq for sim_present
	 */
	irq = platform_get_irq(pdev, 0);
	retval = request_irq(irq,
			mdmgpio_sim_present_handler,
			(IRQF_TRIGGER_RISING |
			IRQF_TRIGGER_FALLING),
			"sim_present", NULL);

	if (retval) {
		printk(KERN_ERR \
			"Unable to request irq %d for sim_present (gpio %d)\n",
			irq, gpio_wan_sim_present);
		goto error;
	}

	return 0;

error:
	mdmgpio_gpio_deinit();
	if (mdmgpio_kobj && mdmgpio_kset)
		kset_unregister(mdmgpio_kset);

	kobject_put(mdmgpio_kobj);
	return retval;
}

static int __devexit mdmgpio_remove(struct platform_device *pdev)
{
	printk(KERN_INFO "%s\n", __func__);
	free_irq(platform_get_irq(pdev, 0), NULL);

	mdmgpio_gpio_deinit();
	kset_unregister(mdmgpio_kset);
	kobject_put(mdmgpio_kobj);

	return 0;
}

static int mdmgpio_suspend(struct platform_device *pdev,
			pm_message_t state)
{
	return 0;
}

static int mdmgpio_resume(struct platform_device *pdev)
{
	return 0;
}

static struct of_device_id mdmgpio_of_match[] __devinitdata = {
	{.compatible = "lab126,mdmgpio", },
	{ },
};

static struct platform_driver mdmgpio_driver = {
	.driver = {
		.name = "mdmgpio",
		.owner  = THIS_MODULE,
		.of_match_table = of_match_ptr(mdmgpio_of_match),
		},
	.suspend = mdmgpio_suspend,
	.resume  = mdmgpio_resume,
	.probe   = mdmgpio_probe,
	.remove  = mdmgpio_remove,
};

static int __init mdmgpio_init(void)
{
	int ret;

	ret = platform_driver_register(&mdmgpio_driver);
	if (ret != 0) {
		printk(KERN_ERR \
			"driver_reg::can not register mdmgpio driver\n");
		return ret;
	}

	return 0;
}

static void mdmgpio_exit(void)
{
	platform_driver_unregister(&mdmgpio_driver);
}

module_init(mdmgpio_init);
module_exit(mdmgpio_exit);

MODULE_DESCRIPTION("Modem GPIO driver");
MODULE_AUTHOR("Ping An Bao <anbao@lab126.com>");
MODULE_LICENSE("GPL");
