#undef TRACE_SYSTEM
#define TRACE_SYSTEM tplms_tp

#if !defined(_TRACE_TPLMSTP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TPLMSTP_H

#include <linux/tracepoint.h>

TRACE_EVENT(tplms_tp,

	TP_PROTO(int sequence),

	TP_ARGS(sequence),

	TP_STRUCT__entry(
		__field(	int,	sequence			)
	),

	TP_fast_assign(
		__entry->sequence	= sequence;
	),

	TP_printk("TPLMS sequence = %08x", __entry->sequence)
);

#endif /* _TRACE_TPLMSTP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
