package control

import (
	"context"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func DeliverNext(ctx context.Context, queue *usage.Queue, sink UsageSink) (UsageResult, bool, error) {
	if queue == nil || sink == nil {
		return UsageResult{}, false, nil
	}
	report, ok := queue.Next()
	if !ok {
		return UsageResult{}, false, nil
	}
	result, err := sink.ReportUsage(ctx, UsageReport{OperationID: report.OperationID, Key: report.Key, Bytes: report.Bytes, Interval: report.Interval, Payload: append([]byte(nil), report.Payload...)})
	if err != nil {
		return UsageResult{}, true, err
	}
	queue.Ack(report.OperationID)
	return result, true, nil
}
