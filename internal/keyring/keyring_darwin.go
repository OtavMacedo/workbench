//go:build darwin && cgo

package keyring

import (
	"errors"

	"github.com/keybase/go-keychain"
)

const service = "workbench.local.v1"

func (System) Get(account string) (string, error) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	item.SetMatchLimit(keychain.MatchLimitOne)
	item.SetReturnData(true)
	results, err := keychain.QueryItem(item)
	if err != nil || len(results) != 1 {
		return "", errors.New("cannot unlock native keychain; unlock your login keychain or restore a backup")
	}
	return string(results[0].Data), nil
}

func (System) Set(account, value string) error {
	item := keychain.NewGenericPassword(service, account, "Workbench encrypted vault", []byte(value), "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	if err := keychain.AddItem(item); err != nil {
		return errors.New("cannot create native keychain entry; no plaintext fallback is used")
	}
	return nil
}

func (System) Delete(account string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	if err := keychain.DeleteItem(item); err != nil {
		return errors.New("cannot delete native keychain entry")
	}
	return nil
}
