package tui

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rivo/tview"
)

var logFile = flag.String("log-file", "", "log file to watch")

func readLogs(logFile string, pushLog func(string)) {
	file, err := os.Open(logFile)
	if err != nil {
		pushLog(err.Error())
	}
	defer file.Close()

	r := bufio.NewReader(file)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		if len(line) > 0 {
			pushLog(string(line))
		}
		if err == io.EOF {
			time.Sleep(time.Second)
		}
	}
}

func Run() {
	app := tview.NewApplication()
	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	pushLog := func(line string) {
		textView.ScrollToEnd()
		fmt.Fprintf(textView, "%s", line)
	}

	go readLogs(*logFile, pushLog)

	textView.SetBorder(true).SetTitle("Request log").SetTitleAlign(tview.AlignLeft)
	if err := app.SetRoot(textView, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
