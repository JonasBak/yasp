package tui

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/jonasbak/yasp/utils"
	"github.com/rivo/tview"
	"io"
	"os"
	"strings"
)

var forwardURL = flag.String("forward-url", "", "")
var mock = flag.Bool("mock", false, "")

func readMessages(pushLog func(string), setSettings func(utils.SessionSettings)) {
	fd3 := os.NewFile(3, "/proc/self/fd/3")

	r := bufio.NewReader(fd3)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		if len(line) > 0 {
			lineStr := string(line)
			if strings.HasPrefix(lineStr, utils.LOG_MSG_PREFIX) {
				pushLog(string(line[len(utils.LOG_MSG_PREFIX):]))
			} else if strings.HasPrefix(lineStr, utils.SETTINGS_MSG_PREFIX) {
				settings := utils.SessionSettings{}
				err := json.Unmarshal(line[len(utils.SETTINGS_MSG_PREFIX):], &settings)
				if err != nil {
					pushLog("[red]could not parse settings[white]\n")
					pushLog(string(line[len(utils.SETTINGS_MSG_PREFIX):]))
				} else {
					setSettings(settings)
				}
			} else {
				pushLog("[red]could not parse last message[white]\n")
			}
		}
		if err == io.EOF {
			pushLog("[red]pipe closed[white]\n")
			return
		}
	}
}

func setSettings(s utils.SessionSettings) {
	settingsStr, _ := json.Marshal(s)
	fmt.Fprintf(os.Stderr, "%s%s\n", utils.SETTINGS_MSG_PREFIX, settingsStr)
}

func Run() {
	app := tview.NewApplication()

	settings := utils.SessionSettings{}

	settingsView := tview.NewForm().
		SetItemPadding(1).
		SetLabelColor(tcell.ColorWhite).
		SetFieldBackgroundColor(tcell.ColorGray).
		AddCheckbox("Allow traffic", true, func(c bool) {
			s := settings
			s.Traffic = c
			setSettings(s)
		}).
		AddPasswordField("Password", "", 10, '*', nil)

	infoView := tview.NewTextView().
		SetDynamicColors(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	infoView.SetTitle(" Status ").SetBorder(true).SetTitleAlign(tview.AlignLeft)

	setStatusText := func() {
		trafficText := "[green]open"
		if !settings.Traffic {
			trafficText = "[red]blocked"
		} else if settings.Password != "" {
			trafficText = "[yellow]auth"
		}
		infoView.SetText(fmt.Sprintf("Your url:\n[blue]%s[white]\nTraffic: %s[white]", *forwardURL, trafficText))
	}
	setStatusText()

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	textView.SetTitle(" Request log ").SetBorder(true).SetTitleAlign(tview.AlignLeft)

	grid := tview.NewGrid().
		SetRows(10, 0, 3).
		SetColumns(30, 0, 30).
		AddItem(settingsView, 0, 0, 1, 2, 0, 0, true).
		AddItem(infoView, 0, 2, 1, 1, 0, 0, false).
		AddItem(textView, 1, 0, 2, 3, 0, 0, false)

	pushLog := func(line string) {
		textView.ScrollToEnd()
		fmt.Fprintf(textView, "%s", line)
	}
	setSettings := func(s utils.SessionSettings) {
		settings = s
		setStatusText()
	}

	if !*mock {
		go readMessages(pushLog, setSettings)
	}

	if err := app.SetRoot(grid, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
