package data

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/oauth2"
)

const dataFileName = "/data/bot.json"

func init() {
	if _, err := os.Stat(dataFileName); errors.Is(err, os.ErrNotExist) {
		err = os.WriteFile(dataFileName, []byte("{}"), 0o666)
		if err != nil {
			panic(err)
		}
	}
}

var m sync.Mutex

func SaveToken(c *oauth2.Token) error {
	m.Lock()
	defer m.Unlock()

	err := save(c)
	if err != nil {
		return fmt.Errorf("save data: %w", err)
	}

	return nil
}

func GetToken() (*oauth2.Token, error) {
	m.Lock()
	defer m.Unlock()

	data, err := read()
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	return data, nil
}

func save(d *oauth2.Token) error {
	b, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	err = os.WriteFile(dataFileName, b, 0o666)
	if err != nil {
		return fmt.Errorf("write to file: %w", err)
	}

	return nil
}

func read() (*oauth2.Token, error) {
	var d oauth2.Token
	b, err := os.ReadFile(dataFileName)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	err = json.Unmarshal(b, &d)
	if err != nil {
		return nil, fmt.Errorf("unmarshal data: %w", err)
	}

	return &d, nil
}
