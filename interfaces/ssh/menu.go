package ssh

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/labbs/bastion/domain"
	"github.com/rs/zerolog"
)

type Menu struct {
	Logger zerolog.Logger
	Hosts  []domain.Host
	Writer io.Writer
	Reader io.Reader
}

func NewMenu(logger zerolog.Logger, hosts []domain.Host, writer io.Writer, reader io.Reader) *Menu {
	return &Menu{
		Logger: logger,
		Hosts:  hosts,
		Writer: writer,
		Reader: reader,
	}
}

func (m *Menu) Display() (int, error) {
	m.Writer.Write([]byte("\n"))
	m.Writer.Write([]byte("=== Bastion SSH - Select Host ===\n"))
	m.Writer.Write([]byte("\n"))

	if len(m.Hosts) == 0 {
		m.Writer.Write([]byte("No hosts available.\n"))
		return -1, fmt.Errorf("no hosts available")
	}

	for i, host := range m.Hosts {
		m.Writer.Write([]byte(fmt.Sprintf("%d. %s (%s:%d)\n", i+1, host.Name, host.Hostname, host.Port)))
		if host.Description != "" {
			m.Writer.Write([]byte(fmt.Sprintf("   %s\n", host.Description)))
		}
	}

	m.Writer.Write([]byte("\n"))
	m.Writer.Write([]byte("Select a host (1-" + strconv.Itoa(len(m.Hosts)) + "): "))

	scanner := bufio.NewScanner(m.Reader)
	if !scanner.Scan() {
		return -1, fmt.Errorf("failed to read input")
	}

	choiceStr := strings.TrimSpace(scanner.Text())
	choice, err := strconv.Atoi(choiceStr)
	if err != nil {
		return -1, fmt.Errorf("invalid selection: %s", choiceStr)
	}

	if choice < 1 || choice > len(m.Hosts) {
		return -1, fmt.Errorf("invalid selection: %d", choice)
	}

	return choice - 1, nil
}

