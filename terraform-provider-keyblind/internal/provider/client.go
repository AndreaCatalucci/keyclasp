package provider

import (
	"fmt"
	"os/exec"
	"strings"
)

type Client struct {
	CLIPath string
}

func NewClient(cliPath string) *Client {
	if cliPath == "" {
		cliPath = "keyblind"
	}
	return &Client{CLIPath: cliPath}
}

func (c *Client) run(args ...string) (string, error) {
	cmd := exec.Command(c.CLIPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("keyblind error: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("failed to run keyblind: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Client) GetSecret(name string) (string, error) {
	return c.run("get", name)
}

func (c *Client) StoreSecret(name, value string) error {
	_, err := c.run("set", name, value)
	return err
}

func (c *Client) DeleteSecret(name string) error {
	_, err := c.run("delete", name)
	return err
}

func (c *Client) ListSecrets() ([]string, error) {
	out, err := c.run("list")
	if err != nil {
		return nil, err
	}
	if out == "(no secrets stored)" {
		return nil, nil
	}
	var secrets []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") {
			secrets = append(secrets, strings.TrimPrefix(line, "- "))
		}
	}
	return secrets, nil
}

func (c *Client) SecretExists(name string) (bool, error) {
	secrets, err := c.ListSecrets()
	if err != nil {
		return false, err
	}
	for _, s := range secrets {
		if strings.EqualFold(s, name) {
			return true, nil
		}
	}
	return false, nil
}
