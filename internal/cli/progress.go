package cli

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

// All updates happen on the transfer goroutine. No timer can print after the
// next prompt, and no background goroutine races with readline or a writer.
type transferProgress struct {
	w                    io.Writer
	operation            string
	enabled, live, color bool
	now                  func() time.Time
	width                func() int
	started, last        time.Time
	done, total          uint64
	seen, finished       bool
}

func newProgress(w io.Writer, operation, source, destination, mode string, tty, color bool) *transferProgress {
	p := &transferProgress{w: w, operation: strings.ToUpper(operation), color: color, now: time.Now, width: readline.GetScreenWidth}
	p.live = tty && os.Getenv("TERM") != "dumb"
	p.enabled = mode == "always" || mode != "never" && p.live
	p.started = p.now()
	if p.enabled {
		fmt.Fprintf(w, "\n  %s  %s -> %s\n", paint(color, p.activeTone(), p.operation), label(source), label(destination))
	}
	return p
}

func (p *transferProgress) Update(done, total uint64) {
	if p.finished {
		return
	}
	p.done, p.total = done, total
	now := p.now()
	if !p.seen || now.Sub(p.last) >= 125*time.Millisecond {
		p.seen = true
		p.render(now, "", false)
	}
}

func durationText(seconds float64) string {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return "--"
	}
	if seconds >= 86400 {
		return fmt.Sprintf("%.0fd", math.Ceil(seconds/86400))
	}
	sec := int(math.Ceil(seconds))
	if sec >= 3600 {
		return fmt.Sprintf("%dh%02dm", sec/3600, sec%3600/60)
	}
	if sec >= 60 {
		return fmt.Sprintf("%dm%02ds", sec/60, sec%60)
	}
	return fmt.Sprintf("%ds", sec)
}

func (p *transferProgress) line(now time.Time, status string, complete bool) string {
	elapsed := max(now.Sub(p.started).Seconds(), 0)
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(p.done) / elapsed
	}
	percent := 0
	if p.total > 0 {
		percent = int(min(99.0, float64(p.done)/float64(p.total)*100))
	}
	if complete {
		percent = 100
	}
	eta := "--"
	if p.done > 0 && p.total > p.done && rate > 0 {
		eta = durationText(float64(p.total-p.done) / rate)
	}
	if p.done >= p.total && p.total > 0 {
		eta = "saving"
	}
	if status != "" {
		eta = status
	}
	speed := "--"
	if rate > 0 {
		speed = humanSize(uint64(min(rate, float64(math.MaxInt64)))) + "/s"
	}
	width := p.width()
	if width <= 0 {
		width = 80
	}
	barWidth := 16
	if width < 90 {
		barWidth = 10
	}
	filled := percent * barWidth / 100
	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
	candidates := []string{
		fmt.Sprintf("  [%s] %3d%%  %s / %s  %s  %s", bar, percent, humanSize(p.done), humanSize(p.total), speed, etaPrefix(eta, status)),
		fmt.Sprintf("  [%s] %3d%%  %s  %s  %s", bar, percent, humanSize(p.done), speed, etaPrefix(eta, status)),
		fmt.Sprintf("  %3d%%  %s  %s", percent, humanSize(p.done), etaPrefix(eta, status)),
		fmt.Sprintf("%d%% %s", percent, eta),
	}
	// Keep the live cursor on one row, including at 60-79 column widths. Leave
	// one spare column because some terminals wrap immediately in the last cell.
	for _, line := range candidates {
		if len(line) < width {
			return line
		}
	}
	return candidates[len(candidates)-1][:max(0, width-1)]
}

func etaPrefix(eta, status string) string {
	if status != "" || eta == "saving" {
		return eta
	}
	return "ETA " + eta
}

func (p *transferProgress) activeTone() string {
	if p.operation == "PUT" {
		return lavender
	}
	return green
}

func (p *transferProgress) render(now time.Time, status string, complete bool) {
	p.last = now
	if !p.enabled {
		return
	}
	line := p.line(now, status, complete)
	tone := p.activeTone()
	if complete {
		tone = green
	} else if status != "" {
		tone = red
	}
	if p.live {
		// CR + erase-line is independent of color (NO_COLOR still has progress).
		fmt.Fprint(p.w, "\r\x1b[2K"+paint(p.color, tone, line))
	} else {
		fmt.Fprintln(p.w, paint(p.color, tone, line))
	}
}

func (p *transferProgress) Finish(done int64, err error) {
	if p.finished {
		return
	}
	p.finished = true
	p.done = uint64(max(done, 0))
	status, tone := "DONE", green
	if err != nil {
		status, tone = "FAILED", red
	}
	now := p.now()
	p.render(now, status, err == nil)
	if p.enabled && p.live {
		fmt.Fprintln(p.w)
	}
	elapsed := max(now.Sub(p.started).Seconds(), 0)
	speed := "--"
	if elapsed > 0 {
		speed = humanSize(uint64(min(float64(p.done)/elapsed, float64(math.MaxInt64)))) + "/s"
	}
	fmt.Fprintf(p.w, "  %s  %s | %s | %s | avg %s\n", paint(p.color, tone, status), p.operation, humanSize(p.done), durationText(elapsed), speed)
}
