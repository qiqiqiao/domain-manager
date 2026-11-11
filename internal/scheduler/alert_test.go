package scheduler

import "testing"

func TestPickThreshold(t *testing.T) {
	thresholds := []int{30, 15, 7, 3, 1, 0}
	tests := []struct {
		days     int
		want     int
		alerting bool
	}{
		{40, 0, false},
		{30, 30, true},
		{25, 30, true},
		{14, 15, true},
		{7, 7, true},
		{0, 0, true},
		{-3, 0, true},
	}
	for _, tc := range tests {
		got, ok := pickThreshold(tc.days, thresholds)
		if got != tc.want || ok != tc.alerting {
			t.Errorf("pickThreshold(%d) = (%d,%v), want (%d,%v)", tc.days, got, ok, tc.want, tc.alerting)
		}
	}
}

func TestPickThresholdEmpty(t *testing.T) {
	if _, ok := pickThreshold(5, nil); ok {
		t.Fatal("empty thresholds should not alert")
	}
}
