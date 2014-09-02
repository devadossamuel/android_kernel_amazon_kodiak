/* Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/iopoll.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>

#include "mdss_fb.h"
#include "mdss_mdp.h"
#include <linux/trapz.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include "mdss_dsi.h"

/* wait for at least 2 vsyncs for lowest refresh rate (24hz) */
#define VSYNC_TIMEOUT_US 100000

#define MDP_INTR_MASK_INTF_VSYNC(intf_num) \
	(1 << (2 * (intf_num - MDSS_MDP_INTF0) + MDSS_MDP_IRQ_INTF_VSYNC))

/*mutex to synchronize PSR and commit thread*/
static DEFINE_MUTEX(mdss_update_lock);
/* intf timing settings */
struct intf_timing_params {
	u32 width;
	u32 height;
	u32 xres;
	u32 yres;

	u32 h_back_porch;
	u32 h_front_porch;
	u32 v_back_porch;
	u32 v_front_porch;
	u32 hsync_pulse_width;
	u32 vsync_pulse_width;

	u32 border_clr;
	u32 underflow_clr;
	u32 hsync_skew;
};

struct mdss_mdp_video_ctx {
	u32 intf_num;
	char __iomem *base;
	u32 intf_type;
	u8 ref_cnt;

	u8 timegen_en;
	bool polling_en;
	u32 poll_cnt;
	struct completion vsync_comp;
	int wait_pending;

	atomic_t vsync_ref;
	spinlock_t vsync_lock;
	struct list_head vsync_handlers;
	struct mdss_mdp_ctl *ctl;
	struct workqueue_struct *intf_psr_wq;
	struct delayed_work intf_psr_worker;
	bool panel_psr_enabled;
	bool panel_psr_on;
};

static inline void mdp_video_write(struct mdss_mdp_video_ctx *ctx,
				   u32 reg, u32 val)
{
	writel_relaxed(val, ctx->base + reg);
}

static void intf_psr_wq_handler(struct work_struct *work)
{
	struct mdss_mdp_video_ctx *ctx;
	int rc;
	struct mdss_panel_data *pdata;
         struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	ktime_t t1,t2, wait_time;
	u32 wait_time_in_ms;

	mutex_lock(&mdss_update_lock);
	if (!work) {
		pr_err("%s: invalid 'work' in handler\n", __func__);
		mutex_unlock(&mdss_update_lock);
		return;
	}
	
	ctx = container_of(to_delayed_work(work),
			   struct mdss_mdp_video_ctx, intf_psr_worker);

	if (!ctx->ctl) {
		pr_err("%s: invalid ctl for ctx\n", __func__);
		mutex_unlock(&mdss_update_lock);
		return;
	}

	pdata = ctx->ctl->panel_data;
	pr_debug("ctl num = %d\n", ctx->ctl->num);
	pr_debug("%s: psr_wq timed-out\n", __func__);

         ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);

	t1 = ktime_get();
	if (ctx->timegen_en) {
		rc = mdss_mdp_ctl_intf_event(ctx->ctl,
			MDSS_EVENT_NO_FRAME_UPDATE, NULL);
		if (rc == -EBUSY) {
			pr_err("intf #%d busy don't turn off\n",
				 ctx->ctl->intf_num);
			mutex_unlock(&mdss_update_lock);
			return;
		}

		/*need to send one complete frame*/
		if(ctrl_pdata->shared_pdata.broadcast_enable){
			wait_for_completion_interruptible_timeout(&ctx->vsync_comp, usecs_to_jiffies(VSYNC_TIMEOUT_US));
			msleep(20);
		}
		
		if (ctx->panel_psr_enabled) {
			mdp_video_write(ctx, MDSS_MDP_REG_INTF_TIMING_ENGINE_EN, 0);
			msleep(20);
			mdss_mdp_irq_disable(MDSS_MDP_IRQ_INTF_UNDER_RUN, ctx->ctl->intf_num); 
			mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF, false);
			ctx->timegen_en = false;

			rc = mdss_mdp_ctl_intf_event(ctx->ctl,
						     MDSS_EVENT_PANEL_OFF, NULL);
			WARN(rc, "intf %d timegen off error (%d)\n", ctx->ctl->intf_num, rc);
			ctx->panel_psr_on = true;
		}
	}
	t2 = ktime_get();
	wait_time = ktime_sub(t2, t1);
	wait_time_in_ms = (u32)ktime_to_ms(wait_time);
	pr_debug("...abhinav..time to do PSR %s: wait_time_in_ms= %d\n", __func__, wait_time_in_ms);

	mutex_unlock(&mdss_update_lock);
}

static inline u32 mdp_video_read(struct mdss_mdp_video_ctx *ctx,
				   u32 reg)
{
	return readl_relaxed(ctx->base + reg);
}

static inline u32 mdss_mdp_video_line_count(struct mdss_mdp_ctl *ctl)
{
	struct mdss_mdp_video_ctx *ctx;
	u32 line_cnt = 0;
	if (!ctl || !ctl->priv_data)
		goto line_count_exit;
	ctx = ctl->priv_data;
	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_ON, false);
	line_cnt = mdp_video_read(ctx, MDSS_MDP_REG_INTF_LINE_COUNT);
	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF, false);
line_count_exit:
	return line_cnt;
}

int mdss_mdp_video_addr_setup(struct mdss_data_type *mdata,
				u32 *offsets,  u32 count)
{
	struct mdss_mdp_video_ctx *head;
	u32 i;

	head = devm_kzalloc(&mdata->pdev->dev,
			sizeof(struct mdss_mdp_video_ctx) * count, GFP_KERNEL);
	if (!head)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		head[i].base = mdata->mdp_base + offsets[i];
		pr_debug("adding Video Intf #%d offset=0x%x virt=%p\n", i,
				offsets[i], head[i].base);
		head[i].ref_cnt = 0;
		head[i].intf_num = i + MDSS_MDP_INTF0;
		INIT_LIST_HEAD(&head[i].vsync_handlers);
	}

	mdata->video_intf = head;
	mdata->nintf = count;
	return 0;
}

static int mdss_mdp_video_timegen_setup(struct mdss_mdp_ctl *ctl,
					struct intf_timing_params *p)
{
	u32 hsync_period, vsync_period;
	u32 hsync_start_x, hsync_end_x, display_v_start, display_v_end;
	u32 active_h_start, active_h_end, active_v_start, active_v_end;
	u32 den_polarity, hsync_polarity, vsync_polarity;
	u32 display_hctl, active_hctl, hsync_ctl, polarity_ctl;
	struct mdss_mdp_video_ctx *ctx;

	ctx = ctl->priv_data;
	hsync_period = p->hsync_pulse_width + p->h_back_porch +
			p->width + p->h_front_porch;
	vsync_period = p->vsync_pulse_width + p->v_back_porch +
			p->height + p->v_front_porch;

	display_v_start = ((p->vsync_pulse_width + p->v_back_porch) *
			hsync_period) + p->hsync_skew;
	display_v_end = ((vsync_period - p->v_front_porch) * hsync_period) +
			p->hsync_skew - 1;

	if (ctx->intf_type == MDSS_INTF_EDP) {
		display_v_start += p->hsync_pulse_width + p->h_back_porch;
		display_v_end -= p->h_front_porch;
	}

	hsync_start_x = p->h_back_porch + p->hsync_pulse_width;
	hsync_end_x = hsync_period - p->h_front_porch - 1;

	if (p->width != p->xres) {
		active_h_start = hsync_start_x;
		active_h_end = active_h_start + p->xres - 1;
	} else {
		active_h_start = 0;
		active_h_end = 0;
	}

	if (p->height != p->yres) {
		active_v_start = display_v_start;
		active_v_end = active_v_start + (p->yres * hsync_period) - 1;
	} else {
		active_v_start = 0;
		active_v_end = 0;
	}


	if (active_h_end) {
		active_hctl = (active_h_end << 16) | active_h_start;
		active_hctl |= BIT(31);	/* ACTIVE_H_ENABLE */
	} else {
		active_hctl = 0;
	}

	if (active_v_end)
		active_v_start |= BIT(31); /* ACTIVE_V_ENABLE */

	hsync_ctl = (hsync_period << 16) | p->hsync_pulse_width;
	display_hctl = (hsync_end_x << 16) | hsync_start_x;

	den_polarity = 0;
	if (MDSS_INTF_HDMI == ctx->intf_type) {
		hsync_polarity = p->yres >= 720 ? 0 : 1;
		vsync_polarity = p->yres >= 720 ? 0 : 1;
	} else {
		hsync_polarity = 0;
		vsync_polarity = 0;
	}
	polarity_ctl = (den_polarity << 2)   | /*  DEN Polarity  */
		       (vsync_polarity << 1) | /* VSYNC Polarity */
		       (hsync_polarity << 0);  /* HSYNC Polarity */

	mdp_video_write(ctx, MDSS_MDP_REG_INTF_HSYNC_CTL, hsync_ctl);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_VSYNC_PERIOD_F0,
			vsync_period * hsync_period);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_VSYNC_PULSE_WIDTH_F0,
			   p->vsync_pulse_width * hsync_period);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_DISPLAY_HCTL, display_hctl);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_DISPLAY_V_START_F0,
			   display_v_start);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_DISPLAY_V_END_F0, display_v_end);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_ACTIVE_HCTL, active_hctl);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_ACTIVE_V_START_F0,
			   active_v_start);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_ACTIVE_V_END_F0, active_v_end);

	mdp_video_write(ctx, MDSS_MDP_REG_INTF_BORDER_COLOR, p->border_clr);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_UNDERFLOW_COLOR,
			   p->underflow_clr);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_HSYNC_SKEW, p->hsync_skew);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_POLARITY_CTL, polarity_ctl);
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_FRAME_LINE_COUNT_EN, 0x3);

	return 0;
}


static inline void video_vsync_irq_enable(struct mdss_mdp_ctl *ctl, bool clear)
{
	struct mdss_mdp_video_ctx *ctx = ctl->priv_data;

	if (atomic_inc_return(&ctx->vsync_ref) == 1)
		mdss_mdp_irq_enable(MDSS_MDP_IRQ_INTF_VSYNC, ctl->intf_num);
	else if (clear)
		mdss_mdp_irq_clear(ctl->mdata, MDSS_MDP_IRQ_INTF_VSYNC,
				ctl->intf_num);
}

static inline void video_vsync_irq_disable(struct mdss_mdp_ctl *ctl)
{
	struct mdss_mdp_video_ctx *ctx = ctl->priv_data;

	if (atomic_dec_return(&ctx->vsync_ref) == 0)
		mdss_mdp_irq_disable(MDSS_MDP_IRQ_INTF_VSYNC, ctl->intf_num);
}

static int mdss_mdp_video_add_vsync_handler(struct mdss_mdp_ctl *ctl,
		struct mdss_mdp_vsync_handler *handle)
{
	struct mdss_mdp_video_ctx *ctx;
	unsigned long flags;
	int ret = 0;
	bool irq_en = false;

	if (!handle || !(handle->vsync_handler)) {
		ret = -EINVAL;
		goto exit;
	}

	ctx = (struct mdss_mdp_video_ctx *) ctl->priv_data;
	if (!ctx) {
		pr_err("invalid ctx for ctl=%d\n", ctl->num);
		ret = -ENODEV;
		goto exit;
	}

	spin_lock_irqsave(&ctx->vsync_lock, flags);
	if (!handle->enabled) {
		handle->enabled = true;
		list_add(&handle->list, &ctx->vsync_handlers);
		irq_en = true;
	}
	spin_unlock_irqrestore(&ctx->vsync_lock, flags);
	if (irq_en)
		video_vsync_irq_enable(ctl, false);
exit:
	return ret;
}

static int mdss_mdp_video_remove_vsync_handler(struct mdss_mdp_ctl *ctl,
		struct mdss_mdp_vsync_handler *handle)
{
	struct mdss_mdp_video_ctx *ctx;
	unsigned long flags;
	bool irq_dis = false;

	ctx = (struct mdss_mdp_video_ctx *) ctl->priv_data;
	if (!ctx) {
		pr_err("invalid ctx for ctl=%d\n", ctl->num);
		return -ENODEV;
	}

	spin_lock_irqsave(&ctx->vsync_lock, flags);
	if (handle->enabled) {
		handle->enabled = false;
		list_del_init(&handle->list);
		irq_dis = true;
	}
	spin_unlock_irqrestore(&ctx->vsync_lock, flags);
	if (irq_dis)
		video_vsync_irq_disable(ctl);
	return 0;
}

static int mdss_mdp_video_stop(struct mdss_mdp_ctl *ctl)
{
	struct mdss_mdp_video_ctx *ctx;
	struct mdss_mdp_vsync_handler *tmp, *handle;
	int rc;

	pr_debug("stop ctl=%d\n", ctl->num);

	ctx = (struct mdss_mdp_video_ctx *) ctl->priv_data;
	if (!ctx) {
		pr_err("invalid ctx for ctl=%d\n", ctl->num);
		return -ENODEV;
	}

	if (((ctl->intf_num == MDSS_MDP_INTF1)
		 || (ctl->intf_num == MDSS_MDP_INTF2))
	    && (ctx->intf_psr_wq != NULL)) {
		cancel_delayed_work_sync(&ctx->intf_psr_worker);
		pr_debug("%s: Flush workqueue\n", __func__);
	}

	if (ctx->timegen_en) {
		rc = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_BLANK, NULL);
		if (rc == -EBUSY) {
			pr_debug("intf #%d busy don't turn off\n",
				 ctl->intf_num);
			return rc;
		}
		WARN(rc, "intf %d blank error (%d)\n", ctl->intf_num, rc);
		if ((ctx->panel_psr_enabled)
			   && (ctx->panel_psr_on)) {
			ctx->panel_psr_on = false;
			pr_debug("%s: psr_on set to false\n", __func__);
		}

		mdp_video_write(ctx, MDSS_MDP_REG_INTF_TIMING_ENGINE_EN, 0);
		mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF, false);
		ctx->timegen_en = false;

		rc = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_PANEL_OFF, NULL);
		WARN(rc, "intf %d timegen off error (%d)\n", ctl->intf_num, rc);

		mdss_mdp_irq_disable(MDSS_MDP_IRQ_INTF_UNDER_RUN,
			ctl->intf_num);
		pr_info("%s: psr_on state=%d\n", __func__, ctx->panel_psr_on);
	}else if ((ctx->panel_psr_enabled)
		   && (ctx->panel_psr_on)) {
		rc = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_BLANK, NULL);
		if (rc == -EBUSY) {
			pr_debug("intf #%d busy don't turn off\n",
				 ctl->intf_num);
			return rc;
		}
		WARN(rc, "intf %d blank error (%d)\n", ctl->intf_num, rc);
		ctx->panel_psr_on = false;
		pr_debug("%s: psr_on set to false\n", __func__);
 	}

	list_for_each_entry_safe(handle, tmp, &ctx->vsync_handlers, list)
		mdss_mdp_video_remove_vsync_handler(ctl, handle);

	mdss_mdp_set_intr_callback(MDSS_MDP_IRQ_INTF_VSYNC, ctl->intf_num,
				   NULL, NULL);
	mdss_mdp_set_intr_callback(MDSS_MDP_IRQ_INTF_UNDER_RUN, ctl->intf_num,
				   NULL, NULL);

	ctx->ref_cnt--;
	ctl->priv_data = NULL;

	return 0;
}

static void mdss_mdp_video_vsync_intr_done(void *arg)
{
	struct mdss_mdp_ctl *ctl = arg;
	struct mdss_mdp_video_ctx *ctx = ctl->priv_data;
	struct mdss_mdp_vsync_handler *tmp;
	ktime_t vsync_time;

	/* ACOS_MOD_BEGIN */
	TRAPZ_DESCRIBE(TRAPZ_KERN_DISP, Vsyncirq, "Primary VSYNC interrupt");
	TRAPZ_LOG(TRAPZ_LOG_DEBUG, TRAPZ_CAT_KERNEL, TRAPZ_KERN_DISP,
			Vsyncirq, 0, 0, 0, 0);
	/* ACOS_MOD_END */
	if (!ctx) {
		pr_err("invalid ctx\n");
		return;
	}

	vsync_time = ktime_get();
	ctl->vsync_cnt++;

	pr_debug("intr ctl=%d vsync cnt=%u vsync_time=%d\n",
		 ctl->num, ctl->vsync_cnt, (int)ktime_to_ms(vsync_time));

	ctx->polling_en = false;
	complete_all(&ctx->vsync_comp);
	spin_lock(&ctx->vsync_lock);
	list_for_each_entry(tmp, &ctx->vsync_handlers, list) {
		tmp->vsync_handler(ctl, vsync_time);
	}
	spin_unlock(&ctx->vsync_lock);
}

static int mdss_mdp_video_pollwait(struct mdss_mdp_ctl *ctl)
{
	struct mdss_mdp_video_ctx *ctx = ctl->priv_data;
	u32 mask, status;
	int rc;

	mask = MDP_INTR_MASK_INTF_VSYNC(ctl->intf_num);

	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_ON, false);
	rc = readl_poll_timeout(ctl->mdata->mdp_base + MDSS_MDP_REG_INTR_STATUS,
		status,
		(status & mask) || try_wait_for_completion(&ctx->vsync_comp),
		1000,
		VSYNC_TIMEOUT_US);
	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF, false);

	if (rc == 0) {
		pr_debug("vsync poll successful! rc=%d status=0x%x\n",
				rc, status);
		ctx->poll_cnt++;
		if (status) {
			struct mdss_mdp_vsync_handler *tmp;
			unsigned long flags;
			ktime_t vsync_time = ktime_get();

			spin_lock_irqsave(&ctx->vsync_lock, flags);
			list_for_each_entry(tmp, &ctx->vsync_handlers, list)
				tmp->vsync_handler(ctl, vsync_time);
			spin_unlock_irqrestore(&ctx->vsync_lock, flags);
		}
	} else {
		pr_warn("vsync poll timed out! rc=%d status=0x%x mask=0x%x\n",
				rc, status, mask);
	}

	return rc;
}

static int mdss_mdp_video_wait4comp(struct mdss_mdp_ctl *ctl, void *arg)
{
	struct mdss_mdp_video_ctx *ctx;
	int rc;

	ctx = (struct mdss_mdp_video_ctx *) ctl->priv_data;
	if (!ctx) {
		pr_err("invalid ctx\n");
		return -ENODEV;
	}

	WARN(!ctx->wait_pending, "waiting without commit! ctl=%d", ctl->num);

	if (ctx->polling_en) {
		rc = mdss_mdp_video_pollwait(ctl);
	} else {
		rc = wait_for_completion_interruptible_timeout(&ctx->vsync_comp,
				usecs_to_jiffies(VSYNC_TIMEOUT_US));
		if (rc < 0) {
			pr_warn("vsync wait interrupted ctl=%d\n", ctl->num);
		} else if (rc == 0) {
			pr_warn("vsync wait timeout %d, fallback to poll mode\n",
					ctl->num);
			ctx->polling_en++;
			rc = mdss_mdp_video_pollwait(ctl);
		}
	}

	if (ctx->wait_pending) {
		ctx->wait_pending = 0;
		video_vsync_irq_disable(ctl);
	}

	return rc;
}

static void mdss_mdp_video_underrun_intr_done(void *arg)
{
	struct mdss_mdp_ctl *ctl = arg;
	if (unlikely(!ctl))
		return;

	ctl->underrun_cnt++;
	pr_debug("display underrun detected for ctl=%d count=%d\n", ctl->num,
			ctl->underrun_cnt);
}

extern int psr_user_enabled;

static int mdss_mdp_video_config_fps(struct mdss_mdp_ctl *ctl, int new_fps)
{
	struct mdss_mdp_video_ctx *ctx;
	struct mdss_panel_data *pdata;
	int rc = 0;
	u32 hsync_period, vsync_period;

	pr_debug("Updating fps for ctl=%d\n", ctl->num);

	ctx = (struct mdss_mdp_video_ctx *) ctl->priv_data;
	if (!ctx) {
		pr_err("invalid ctx\n");
		return -ENODEV;
	}

	pdata = ctl->panel_data;
	if (pdata == NULL) {
		pr_err("%s: Invalid panel data\n", __func__);
		return -EINVAL;
	}

	if (!pdata->panel_info.dynamic_fps) {
		pr_err("%s: Dynamic fps not enabled for this panel\n",
						__func__);
		return -EINVAL;
	}

	vsync_period = mdss_panel_get_vtotal(&pdata->panel_info);
	hsync_period = mdss_panel_get_htotal(&pdata->panel_info);

	if (pdata->panel_info.dfps_update
			!= DFPS_SUSPEND_RESUME_MODE) {
		if (pdata->panel_info.dfps_update
				== DFPS_IMMEDIATE_CLK_UPDATE_MODE) {
			if (!ctx->timegen_en) {
				pr_err("TG is OFF. DFPS mode invalid\n");
				return -EINVAL;
			}
			ctl->force_screen_state = MDSS_SCREEN_FORCE_BLANK;
			mdss_mdp_display_commit(ctl, NULL);
			mdss_mdp_display_wait4comp(ctl);
			mdp_video_write(ctx,
					MDSS_MDP_REG_INTF_TIMING_ENGINE_EN, 0);
			/*
			 * Need to wait for atleast one vsync time for proper
			 * TG OFF before doing changes on interfaces
			 */
			msleep(20);
			rc = mdss_mdp_ctl_intf_event(ctl,
						MDSS_EVENT_PANEL_UPDATE_FPS,
						(void *)new_fps);
			WARN(rc, "intf %d panel fps update error (%d)\n",
							ctl->intf_num, rc);
			mdp_video_write(ctx,
					MDSS_MDP_REG_INTF_TIMING_ENGINE_EN, 1);
			/*
			 * Add memory barrier to make sure the MDP Video
			 * mode engine is enabled before next frame is sent
			 */
			mb();
			ctl->force_screen_state = MDSS_SCREEN_DEFAULT;
			mdss_mdp_display_commit(ctl, NULL);
			mdss_mdp_display_wait4comp(ctl);
		} else {
			pr_err("intf %d panel, unknown FPS mode\n",
							ctl->intf_num);
			return -EINVAL;
		}
	} else {
		rc = mdss_mdp_ctl_intf_event(ctl,
					MDSS_EVENT_PANEL_UPDATE_FPS,
					(void *)new_fps);
		WARN(rc, "intf %d panel fps update error (%d)\n",
						ctl->intf_num, rc);
	}

	return rc;
}

static int mdss_mdp_video_display(struct mdss_mdp_ctl *ctl, void *arg)
{
	struct mdss_mdp_video_ctx *ctx;
	int rc;

	mutex_lock(&mdss_update_lock);
	pr_debug("kickoff ctl=%d\n", ctl->num);

	ctx = (struct mdss_mdp_video_ctx *) ctl->priv_data;
	if (!ctx) {
		pr_err("invalid ctx\n");
		mutex_unlock(&mdss_update_lock);
		return -ENODEV;
	}

	if (((ctl->intf_num == MDSS_MDP_INTF1)
		 || (ctl->intf_num == MDSS_MDP_INTF2))
	    && (ctx->intf_psr_wq != NULL)) {
		if (delayed_work_pending(&ctx->intf_psr_worker)) {
			cancel_delayed_work_sync(&ctx->intf_psr_worker);
		}

		pr_debug("%s: Next frame updated\n", __func__);
		rc = mdss_mdp_ctl_intf_event(ctl,
									 MDSS_EVENT_FRAME_UPDATE, NULL);
		WARN(rc, "intf %d frame update error (%d)\n", ctl->intf_num, rc);

		if (psr_user_enabled) {
			queue_delayed_work(ctx->intf_psr_wq,
						   &ctx->intf_psr_worker, msecs_to_jiffies(5000));
			pr_debug("%s: Enable work queue for PSR\n", __func__);
		}
	}

	if (!ctx->wait_pending) {
		ctx->wait_pending++;
		video_vsync_irq_enable(ctl, true);
		INIT_COMPLETION(ctx->vsync_comp);
	} else {
		WARN(1, "commit without wait! ctl=%d", ctl->num);
	}

	if (!ctx->timegen_en) {
		if (!(ctx->panel_psr_enabled && ctx->panel_psr_on)) {
			pr_err("%s: posting UNBLANK event\n", __func__);
			rc = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_UNBLANK, NULL);
			WARN(rc, "intf %d unblank error (%d)\n", ctl->intf_num, rc);
		}
		pr_debug("%s:psr_enabled=%d, panel_psr_on=%d\n",__func__, ctx->panel_psr_enabled,
		       ctx->panel_psr_on);

		pr_debug("enabling timing gen for intf=%d\n", ctl->intf_num);

		mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_ON, false);

		mdss_mdp_irq_enable(MDSS_MDP_IRQ_INTF_UNDER_RUN, ctl->intf_num);
		mdp_video_write(ctx, MDSS_MDP_REG_INTF_TIMING_ENGINE_EN, 1);
		wmb();

		rc = wait_for_completion_timeout(&ctx->vsync_comp,
				usecs_to_jiffies(VSYNC_TIMEOUT_US));
		WARN(rc == 0, "timeout (%d) enabling timegen on ctl=%d\n",
				rc, ctl->num);

		ctx->timegen_en = true;
		rc = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_PANEL_ON, NULL);
		WARN(rc, "intf %d panel on error (%d)\n", ctl->intf_num, rc);
	}
	mutex_unlock(&mdss_update_lock);
	return 0;
}

static struct splash_pipe_cfg splash_pipes[MDSS_MDP_MAX_SSPP];

int mdss_mdp_scan_cont_splash(void)
{
	u32 off;
	u32  data, height = 0, width = 0;
	int i, j, total = 0;
	u32 bits;
	struct splash_pipe_cfg *sp;

	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_ON, false);
	sp = splash_pipes;
	for (i = 0; i < MDSS_MDP_MAX_SSPP; i++, sp++) {
		off = MDSS_MDP_REG_SSPP_OFFSET(i) + MDSS_MDP_REG_SSPP_SRC_SIZE;
		data = MDSS_MDP_REG_READ(off);
		pr_debug("i=%d: addr=%x hw=%x\n", i, (int)off, (int)data);

		if (data == 0)
			continue;
		height = data;
		height >>= 16;
		height &= 0x0ffff;
		width = data & 0x0ffff;
		sp->width = width;
		sp->height = height;
		total++;
	}
	off = MDSS_MDP_REG_CTL_OFFSET(0);	/* control 0 only */
	for (i = 0; i < MDSS_MDP_INTF_MAX_LAYERMIXER; i++) {
		data = MDSS_MDP_REG_READ(off);
		pr_debug("i=%d: addr=%x hw=%x\n", i, (int)off, (int)data);

		for (j = 0; j < MDSS_MDP_MAX_SSPP; j++) {
			bits = data & 0x07;
			if (bits)
				splash_pipes[j].mixer = i;
			data >>= 3;
		}
		off += 4;
	}
	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF, false);

	pr_debug("total=%d\n", total);

	return total;
}

int mdss_mdp_video_copy_splash_screen(struct mdss_panel_data *pdata)
{
	void *virt = NULL;
	unsigned long fb_addr = 0;
	unsigned long *fb_addr_va;
	unsigned long  off;
	u32 height, width, bpp, flush;
	size_t size;
	static struct ion_handle *ihdl;
	struct ion_client *iclient = mdss_get_ionclient();
	static ion_phys_addr_t phys;
	int i;
	struct splash_pipe_cfg *sp;

	sp = splash_pipes;

	width = 0;
	height = 0;
	for (i = 0; i < 8; i++, sp++) {
		if (sp->width == 0)
			continue;
		width += sp->width;	/* aggregated */
		height = sp->height;
		off = MDSS_MDP_REG_SSPP_OFFSET(i) +
		MDSS_MDP_REG_SSPP_SRC0_ADDR;
		fb_addr = MDSS_MDP_REG_READ(off);
	}

	bpp        = 3;
	size = PAGE_ALIGN(height * width * bpp);
	pr_debug("splash_height=%d splash_width=%d Buffer size=%d fb=%x\n",
			height, width, size, (int)fb_addr);

	ihdl = ion_alloc(iclient, size, SZ_1M,
			ION_HEAP(ION_QSECOM_HEAP_ID), 0);
	if (IS_ERR_OR_NULL(ihdl)) {
		pr_err("unable to alloc fbmem from ion (%p)\n", ihdl);
		return -ENOMEM;
	}

	pdata->panel_info.splash_ihdl = ihdl;

	virt = ion_map_kernel(iclient, ihdl);
	ion_phys(iclient, ihdl, &phys, &size);

	pr_debug("%s %d Allocating %u bytes at 0x%lx (%pa phys)\n",
			__func__, __LINE__, size,
			(unsigned long int)virt, &phys);

	fb_addr_va = (unsigned long *)ioremap(fb_addr, size);
	memcpy(virt, fb_addr_va, size);
	iounmap(fb_addr_va);

	sp = splash_pipes;
	flush = 0;
	for (i = 0; i < 8; i++, sp++) {
		if (sp->width == 0)
			continue;
		off = MDSS_MDP_REG_SSPP_OFFSET(i) +
			MDSS_MDP_REG_SSPP_SRC0_ADDR;
		MDSS_MDP_REG_WRITE(off, phys);
		flush |= (1 << i);	/* pipe bit */
		flush |= (4 << sp->mixer); /* mixer bit */
	}

	MDSS_MDP_REG_WRITE(MDSS_MDP_REG_CTL_FLUSH + MDSS_MDP_REG_CTL_OFFSET(0),
					flush);

	return 0;
}

int mdss_mdp_video_reconfigure_splash_done(struct mdss_mdp_ctl *ctl)
{
	struct mdss_panel_data *pdata;
	int ret = 0, off;
	int mdss_mdp_rev = MDSS_MDP_REG_READ(MDSS_MDP_REG_HW_VERSION);
	int mdss_v2_intf_off = 0;
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(ctl->mfd);

	off = 0;

	pdata = ctl->panel_data;

	pdata->panel_info.cont_splash_enabled = 0;

	ret = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_CONT_SPLASH_BEGIN,
								  NULL);
	if (ret) {
		pr_err("%s: Failed to handle 'CONT_SPLASH_BEGIN' event\n",
			   __func__);
		return ret;
	}
	mdss_mdp_ctl_write(ctl, 0, MDSS_MDP_LM_BORDER_COLOR);
	off = MDSS_MDP_REG_INTF_OFFSET(ctl->intf_num);

	if (mdss_mdp_rev == MDSS_MDP_HW_REV_102)
		mdss_v2_intf_off =  0xEC00;

	MDSS_MDP_REG_WRITE(off + MDSS_MDP_REG_INTF_TIMING_ENGINE_EN -
			mdss_v2_intf_off, 0);
	/* wait for 1 VSYNC for the pipe to be unstaged */
	msleep(20);

	/* Give back the reserved memory to the system */
	memblock_free(mdp5_data->splash_mem_addr, mdp5_data->splash_mem_size);
	free_bootmem_late(mdp5_data->splash_mem_addr, mdp5_data->splash_mem_size);

	ret = mdss_mdp_ctl_intf_event(ctl, MDSS_EVENT_CONT_SPLASH_FINISH,
			NULL);
	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF, false);
	return ret;
}

int mdss_mdp_video_start(struct mdss_mdp_ctl *ctl)
{
	struct mdss_data_type *mdata;
	struct mdss_panel_info *pinfo;
	struct mdss_mdp_video_ctx *ctx;
	struct mdss_mdp_mixer *mixer;
	struct intf_timing_params itp = {0};
	u32 dst_bpp;
	int i;

	mdata = ctl->mdata;
	pinfo = &ctl->panel_data->panel_info;
	mixer = mdss_mdp_mixer_get(ctl, MDSS_MDP_MIXER_MUX_LEFT);

	if (!mixer) {
		pr_err("mixer not setup correctly\n");
		return -ENODEV;
	}

	i = ctl->intf_num - MDSS_MDP_INTF0;
	if (i < mdata->nintf) {
		ctx = ((struct mdss_mdp_video_ctx *) mdata->video_intf) + i;
		if (ctx->ref_cnt) {
			pr_err("Intf %d already in use\n", ctl->intf_num);
			return -EBUSY;
		}
		pr_debug("video Intf #%d base=%p", ctx->intf_num, ctx->base);
		ctx->ref_cnt++;
	} else {
		pr_err("Invalid intf number: %d\n", ctl->intf_num);
		return -EINVAL;
	}

	pr_debug("start ctl=%u\n", ctl->num);

	ctl->priv_data = ctx;
	ctx->intf_type = ctl->intf_type;
	init_completion(&ctx->vsync_comp);
	spin_lock_init(&ctx->vsync_lock);
	atomic_set(&ctx->vsync_ref, 0);

	mdss_mdp_set_intr_callback(MDSS_MDP_IRQ_INTF_VSYNC, ctl->intf_num,
				   mdss_mdp_video_vsync_intr_done, ctl);
	mdss_mdp_set_intr_callback(MDSS_MDP_IRQ_INTF_UNDER_RUN, ctl->intf_num,
				   mdss_mdp_video_underrun_intr_done, ctl);

	dst_bpp = pinfo->fbc.enabled ? (pinfo->fbc.target_bpp) : (pinfo->bpp);

	itp.width = mult_frac((pinfo->xres + pinfo->lcdc.xres_pad),
				dst_bpp, pinfo->bpp);
	itp.height = pinfo->yres + pinfo->lcdc.yres_pad;
	itp.border_clr = pinfo->lcdc.border_clr;
	itp.underflow_clr = pinfo->lcdc.underflow_clr;
	itp.hsync_skew = pinfo->lcdc.hsync_skew;

	itp.xres =  mult_frac(pinfo->xres, dst_bpp, pinfo->bpp);
	itp.yres = pinfo->yres;
	itp.h_back_porch =  mult_frac(pinfo->lcdc.h_back_porch, dst_bpp,
			pinfo->bpp);
	itp.h_front_porch = mult_frac(pinfo->lcdc.h_front_porch, dst_bpp,
			pinfo->bpp);
	itp.v_back_porch =  mult_frac(pinfo->lcdc.v_back_porch, dst_bpp,
			pinfo->bpp);
	itp.v_front_porch = mult_frac(pinfo->lcdc.v_front_porch, dst_bpp,
			pinfo->bpp);
	itp.hsync_pulse_width = mult_frac(pinfo->lcdc.h_pulse_width, dst_bpp,
			pinfo->bpp);
	itp.vsync_pulse_width = pinfo->lcdc.v_pulse_width;

	if (mdss_mdp_video_timegen_setup(ctl, &itp)) {
		pr_err("unable to get timing parameters\n");
		return -EINVAL;
	}
	mdp_video_write(ctx, MDSS_MDP_REG_INTF_PANEL_FORMAT, ctl->dst_format);

	ctl->stop_fnc = mdss_mdp_video_stop;
	ctl->display_fnc = mdss_mdp_video_display;
	ctl->wait_fnc = mdss_mdp_video_wait4comp;
	ctl->read_line_cnt_fnc = mdss_mdp_video_line_count;
	ctl->add_vsync_handler = mdss_mdp_video_add_vsync_handler;
	ctl->remove_vsync_handler = mdss_mdp_video_remove_vsync_handler;
	if ((pinfo->mipi.panel_psr_mode)
	    && ((ctl->intf_num == MDSS_MDP_INTF1)
			|| (ctl->intf_num == MDSS_MDP_INTF2)))
		if (ctx->intf_psr_wq == NULL) {
			ctx->intf_psr_wq =
				create_singlethread_workqueue("intf_psr_workqueue");
			INIT_DELAYED_WORK(&ctx->intf_psr_worker,
							  intf_psr_wq_handler);
			pr_debug("%s: created psr_wq\n", __func__);
			ctx->ctl = ctl;
			ctx->panel_psr_enabled = true;
			ctx->panel_psr_on = false;
		}
	ctl->config_fps_fnc = mdss_mdp_video_config_fps;

	return 0;
}