package app

import (
	"errors"
	"fmt"

	"github.com/pedroloch/workbench/internal/vault"
)

func (a *App) classify(s *vault.Store, args []string) error {
	f := flags("classify")
	public := f.Bool("public", false, "allow get to display the value")
	secret := f.Bool("secret", false, "mask the value in get")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *public == *secret {
		return errors.New("usage: classify PATH --public|--secret")
	}
	p, err := vault.Path(pos[0], false)
	if err != nil {
		return err
	}
	if err := s.Classify(p, *secret); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Classification updated; value remains encrypted")
	return nil
}
