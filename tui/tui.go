package tui

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rivo/tview"
)

var url = flag.String("url", "", "")
var mock = flag.Bool("mock", false, "")

func readLogs(pushLog func(string)) {
	fd3 := os.NewFile(3, "/proc/self/fd/3")

	r := bufio.NewReader(fd3)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		if len(line) > 0 {
			pushLog(string(line))
		}
		if err == io.EOF {
			pushLog("[red]pipe closed")
			return
		}
	}
}

func Run() {
	app := tview.NewApplication()

	newPrimitive := func(text string) tview.Primitive {
		return tview.NewTextView().
			SetTextAlign(tview.AlignCenter).
			SetText(text)
	}

	infoView := tview.NewTextView().
		SetDynamicColors(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	infoView.SetText(fmt.Sprintf("Your url:\n[blue]%s", *url))

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	textView.SetTitle("Request log").SetTitleAlign(tview.AlignLeft)

	grid := tview.NewGrid().
		SetRows(5, 0, 3).
		SetColumns(30, 0, 30).
		SetBorders(true).
		AddItem(newPrimitive("TEST"), 0, 0, 1, 2, 0, 0, false).
		AddItem(infoView, 0, 2, 1, 1, 0, 0, false).
		AddItem(textView, 1, 0, 2, 3, 0, 0, false)

	pushLog := func(line string) {
		textView.ScrollToEnd()
		fmt.Fprintf(textView, "%s", line)
	}

	if !*mock {
		go readLogs(pushLog)
	}

	if err := app.SetRoot(grid, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
