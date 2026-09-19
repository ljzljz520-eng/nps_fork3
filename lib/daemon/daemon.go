package daemon

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/serverreload"
)

var (
	processExistsFn    = processExists
	terminateProcessFn = terminateProcess
	signalReloadFn     = signalReload
)

func init() {
	initReloadListener()
}

func initReloadListener() {
	if common.IsWindows() {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.Signal(10))
	go func() {
		for range signals {
			if err := serverreload.ReloadCurrentConfig(); err != nil {
				logs.Warn("reload config failed: %v", err)
			}
		}
	}()
}

func InitDaemon(f string, runPath string, pidPath string) {
	if len(os.Args) < 2 {
		return
	}
	var args []string
	args = append(args, os.Args[0])
	if len(os.Args) >= 2 {
		args = append(args, os.Args[2:]...)
	}
	args = append(args, "-log=file")
	switch os.Args[1] {
	case "start":
		start(args, f, pidPath, runPath)
		os.Exit(0)
	case "stop":
		stop(f, args[0], pidPath)
		os.Exit(0)
	case "restart":
		stop(f, args[0], pidPath)
		start(args, f, pidPath, runPath)
		os.Exit(0)
	case "status":
		if status(f, pidPath) {
			log.Printf("%s is running", f)
		} else {
			log.Printf("%s is not running", f)
		}
		os.Exit(0)
	case "reload":
		reload(f, pidPath)
		os.Exit(0)
	}
}

func pidFilePath(f string, pidPath string) string {
	return filepath.Join(pidPath, f+".pid")
}

func readPID(pidFile string) (int, error) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pidText := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid %q", pidText)
	}
	return pid, nil
}

func processExists(pid int) bool {
	if common.IsWindows() {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
		out, err := cmd.Output()
		if err != nil {
			return false
		}
		record, err := csv.NewReader(strings.NewReader(strings.TrimSpace(string(out)))).Read()
		if err != nil || len(record) < 2 {
			return false
		}
		foundPID, err := strconv.Atoi(strings.TrimSpace(record[1]))
		return err == nil && foundPID == pid
	}
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "pid=")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == strconv.Itoa(pid)
}

// gracefulTerminateTimeout is how long the service manager waits for the
// process to exit after a graceful termination signal before forcing it.
const gracefulTerminateTimeout = 10 * time.Second

// waitProcessExit polls for the process to disappear.
func waitProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !processExistsFn(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func terminateProcess(pid int) error {
	if common.IsWindows() {
		// Request a graceful close first; force the process if it remains.
		if err := exec.Command("taskkill", "/PID", strconv.Itoa(pid)).Run(); err == nil &&
			waitProcessExit(pid, gracefulTerminateTimeout) {
			return nil
		}
		return exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).Run()
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			return proc.Signal(syscall.SIGKILL)
		}
		return nil
	}
	if waitProcessExit(pid, gracefulTerminateTimeout) {
		return nil
	}
	// Grace period elapsed: force termination.
	return proc.Signal(syscall.SIGKILL)
}

func signalReload(pid int) error {
	if common.IsWindows() {
		return errors.New("reload unsupported on windows")
	}
	return exec.Command("kill", "-USR1", strconv.Itoa(pid)).Run()
}

func reload(f string, pidPath string) {
	if common.IsWindows() {
		log.Println("reload unsupported on windows")
		return
	}
	if f == "nps" && !status(f, pidPath) {
		log.Println("reload fail")
		return
	}
	pid, err := readPID(pidFilePath(f, pidPath))
	if err != nil {
		log.Println("reload error,", err)
		return
	}
	if signalReloadFn(pid) == nil {
		log.Println("reload success")
	} else {
		log.Println("reload fail")
	}
}

func status(f string, pidPath string) bool {
	pid, err := readPID(pidFilePath(f, pidPath))
	if err != nil {
		return false
	}
	return processExistsFn(pid)
}

func start(osArgs []string, f string, pidPath, runPath string) {
	if status(f, pidPath) {
		log.Printf(" %s is running", f)
		return
	}
	cmd := exec.Command(osArgs[0], osArgs[1:]...)
	if runPath != "" {
		cmd.Dir = runPath
	}
	err := cmd.Start()
	if err != nil {
		log.Println("start error", err.Error())
		return
	}
	if cmd.Process.Pid > 0 {
		log.Println("start ok , pid:", cmd.Process.Pid, "working directory:", runPath)
		d1 := []byte(strconv.Itoa(cmd.Process.Pid))
		_ = os.WriteFile(pidFilePath(f, pidPath), d1, 0600)
	} else {
		log.Println("start error")
	}
}

func stop(f string, p string, pidPath string) {
	if !status(f, pidPath) {
		log.Printf(" %s is not running", f)
		return
	}
	pid, err := readPID(pidFilePath(f, pidPath))
	if err != nil {
		log.Println("stop error,", err)
		return
	}
	err = terminateProcessFn(pid)
	if err != nil {
		log.Println("stop error,", err)
	} else {
		log.Println("stop ok")
	}
}
