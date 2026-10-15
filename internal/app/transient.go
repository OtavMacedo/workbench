package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pedroloch/workbench/internal/vault"
	"golang.org/x/term"
)

func (a *App) readValue(stdin, jsonValue bool) (json.RawMessage, error) {
	var value []byte
	var err error
	if stdin {
		value, err = io.ReadAll(io.LimitReader(a.In, (1<<20)+1))
		if err != nil || len(value) > 1<<20 {
			return nil, errors.New("cannot read value or value exceeds 1 MiB")
		}
	} else {
		in, ok := a.In.(*os.File)
		if !ok || !term.IsTerminal(int(in.Fd())) {
			return nil, errors.New("value input needs a terminal or --stdin")
		}
		fmt.Fprint(a.Err, "Value (hidden): ")
		value, err = term.ReadPassword(int(in.Fd()))
		fmt.Fprintln(a.Err)
		if err != nil {
			return nil, errors.New("cannot read value")
		}
	}
	var raw json.RawMessage
	if jsonValue {
		raw = value
	} else {
		raw, _ = json.Marshal(string(value))
	}
	if err := vault.Scalar(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (a *App) seal(args []string) error {
	f := flags("seal")
	to := f.String("to", "", "recipient public key; defaults to your vault")
	as := f.String("as", ".temporary.value", "suggested path if explicitly imported")
	stdin := f.Bool("stdin", false, "read value from stdin")
	jsonValue := f.Bool("json", false, "parse a JSON scalar")
	out := f.String("out", "", "new encrypted output file; defaults to stdout")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errors.New("usage: seal [--to KEY] [--as PATH] [--stdin] [--json] [--out FILE]; values are never accepted as arguments")
	}
	p, err := vault.Path(*as, false)
	if err != nil {
		return err
	}
	if *to == "" {
		s, err := a.open(a.Session)
		if err != nil {
			return err
		}
		*to = s.Identity()
	}
	raw, err := a.readValue(*stdin, *jsonValue)
	if err != nil {
		return err
	}
	packet, err := vault.Seal(p, vault.Entry{Value: raw, Secret: true}, *to)
	if err != nil {
		return err
	}
	return a.output(packet, *out)
}

func (a *App) use(s *vault.Store, args []string) error {
	split := -1
	for i, arg := range args {
		if arg == "--" {
			split = i
			break
		}
	}
	if split < 0 || split == len(args)-1 {
		return errors.New("usage: use FILE|- --env ENV_VAR -- COMMAND [ARGS]")
	}
	f := flags("use")
	variable := f.String("env", "", "environment variable for the decrypted scalar")
	pos, err := parse(f, args[:split])
	if err != nil {
		return err
	}
	if len(pos) != 1 || !validVariable(*variable) {
		return errors.New("usage: use FILE|- --env ENV_VAR -- COMMAND [ARGS]")
	}
	b, err := a.input(pos[0])
	if err != nil {
		return err
	}
	share, err := s.InspectShare(b)
	if err != nil {
		return err
	}
	return a.execute(args[split+1:], map[string]string{*variable: vault.Display(share.Entry.Value)})
}
