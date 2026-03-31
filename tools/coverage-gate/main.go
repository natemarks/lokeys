package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type requirement struct {
	file       string
	fileSuffix string
	minimum    float64
}

type coverageTotals struct {
	covered int
	total   int
}

func main() {
	var profilePath string
	var requires multiFlag

	flag.StringVar(&profilePath, "profile", "", "path to Go coverprofile")
	flag.Var(&requires, "require", "required file coverage in the form path=percent (repeatable)")
	flag.Parse()

	if strings.TrimSpace(profilePath) == "" {
		fatalf("--profile is required")
	}
	if len(requires) == 0 {
		fatalf("at least one --require path=percent must be provided")
	}

	reqs, err := parseRequirements(requires)
	if err != nil {
		fatalf("parse requirements: %v", err)
	}

	fileTotals, err := parseCoverageProfile(profilePath)
	if err != nil {
		fatalf("parse profile: %v", err)
	}

	failed := false
	for _, req := range reqs {
		totals, ok := findTotalsBySuffix(fileTotals, req.fileSuffix)
		if !ok || totals.total == 0 {
			fmt.Printf("coverage gate FAIL %s: no coverage data found (required >= %.1f%%)\n", req.file, req.minimum)
			failed = true
			continue
		}

		pct := (float64(totals.covered) / float64(totals.total)) * 100
		if pct < req.minimum {
			fmt.Printf("coverage gate FAIL %s: %.1f%% < %.1f%%\n", req.file, pct, req.minimum)
			failed = true
			continue
		}
		fmt.Printf("coverage gate PASS %s: %.1f%% >= %.1f%%\n", req.file, pct, req.minimum)
	}

	if failed {
		os.Exit(1)
	}
}

func findTotalsBySuffix(fileTotals map[string]coverageTotals, suffix string) (coverageTotals, bool) {
	var out coverageTotals
	found := false
	for file, totals := range fileTotals {
		if strings.HasSuffix(filepath.ToSlash(file), filepath.ToSlash(suffix)) {
			out.covered += totals.covered
			out.total += totals.total
			found = true
		}
	}
	return out, found
}

type multiFlag []string

func (m *multiFlag) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func parseRequirements(values []string) ([]requirement, error) {
	result := make([]requirement, 0, len(values))
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid require %q (want path=percent)", value)
		}
		file := filepath.ToSlash(strings.TrimSpace(parts[0]))
		if file == "" {
			return nil, fmt.Errorf("invalid require %q: empty path", value)
		}
		minimum, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			return nil, fmt.Errorf("invalid require %q: %w", value, err)
		}
		if minimum < 0 || minimum > 100 {
			return nil, fmt.Errorf("invalid require %q: percent must be 0..100", value)
		}
		result = append(result, requirement{file: file, fileSuffix: file, minimum: minimum})
	}
	return result, nil
}

func parseCoverageProfile(path string) (map[string]coverageTotals, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	totals := map[string]coverageTotals{}
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if lineNo == 1 {
			if !strings.HasPrefix(line, "mode:") {
				return nil, fmt.Errorf("line 1: missing coverprofile mode header")
			}
			continue
		}

		file, statements, count, err := parseCoverageLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		entry := totals[file]
		entry.total += statements
		if count > 0 {
			entry.covered += statements
		}
		totals[file] = entry
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return totals, nil
}

func parseCoverageLine(line string) (file string, statements int, count int, err error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", 0, 0, errors.New("expected three fields")
	}

	left := fields[0]
	colon := strings.Index(left, ":")
	if colon <= 0 {
		return "", 0, 0, fmt.Errorf("invalid block field %q", left)
	}
	file = filepath.ToSlash(left[:colon])
	statements, err = strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid statement count %q", fields[1])
	}
	count, err = strconv.Atoi(fields[2])
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid execution count %q", fields[2])
	}
	return file, statements, count, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
