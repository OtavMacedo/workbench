package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/pedroloch/workbench/internal/keyring"
	"github.com/pedroloch/workbench/internal/ui"
	"github.com/pedroloch/workbench/internal/vault"
	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
)

const Version = "0.1.0"

var errNoTerminal = errors.New("a terminal is required for the passphrase; automation can use a private --password-file")

type App struct {
	In           io.Reader
	Out          io.Writer
	Err          io.Writer
	Ring         keyring.Backend
	Session      keyring.Cache
	Copy         func(string) error
	Exec         func(string, []string, []string) error
	dir          string
	passwordFile string
}

func New() *App {
	return &App{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Ring: keyring.System{}, Session: keyring.Session{}, Copy: Clipboard, Exec: syscall.Exec}
}

func (a *App) Run(args []string) int {
	if err := a.run(args); err != nil {
		fmt.Fprintln(a.Err, "workbench:", err)
		return 1
	}
	return 0
}

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

// Reorder known flags so the documented command PATH --option form works.
func parse(f *flag.FlagSet, args []string) ([]string, error) {
	options, positional := []string{}, []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		definition := f.Lookup(name)
		if definition == nil {
			return nil, errors.New("unknown option; run workbench help")
		}
		options = append(options, arg)
		isBool := false
		if v, ok := definition.Value.(interface{ IsBoolFlag() bool }); ok {
			isBool = v.IsBoolFlag()
		}
		if !strings.Contains(arg, "=") && !isBool {
			i++
			if i >= len(args) {
				return nil, errors.New("option requires a value")
			}
			options = append(options, args[i])
		}
	}
	if err := f.Parse(options); err != nil {
		return nil, errors.New("invalid options; run workbench help")
	}
	return positional, nil
}

func (a *App) password(file, prompt string, confirm bool) (string, error) {
	if file != "" {
		b, err := vault.ReadInput(file, true)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	f, ok := a.In.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errNoTerminal
	}
	fmt.Fprint(a.Err, prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(a.Err)
	if err != nil {
		return "", errors.New("cannot read passphrase")
	}
	if confirm {
		fmt.Fprint(a.Err, "Confirm passphrase: ")
		second, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.Err)
		if err != nil || string(b) != string(second) {
			return "", errors.New("passphrases do not match")
		}
	}
	return string(b), nil
}

func (a *App) confirm(message string) (bool, error) {
	f, ok := a.In.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false, errors.New("confirmation requires a terminal; use the documented explicit confirmation flag for automation")
	}
	fmt.Fprint(a.Err, message+" [y/N]: ")
	line, err := bufio.NewReader(a.In).ReadString('\n')
	if err != nil {
		return false, errors.New("cannot read confirmation")
	}
	return strings.EqualFold(strings.TrimSpace(line), "y"), nil
}

func (a *App) open(cache keyring.Cache) (*vault.Store, error) {
	return vault.Open(a.dir, a.Ring, cache, func() (string, error) {
		pass, err := a.password(a.passwordFile, "Vault passphrase: ", false)
		if errors.Is(err, errNoTerminal) && cache != nil && runtime.GOOS == "linux" {
			return "", errors.New("vault is locked; run wkb unlock in your terminal, or use a private --password-file for automation")
		}
		return pass, err
	})
}

func (a *App) run(args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("cannot find home directory")
	}
	a.dir = filepath.Join(home, ".config", "workbench")
	g := flags("workbench")
	g.StringVar(&a.dir, "dir", a.dir, "vault directory")
	g.StringVar(&a.passwordFile, "password-file", "", "private passphrase file for automation")
	help := g.Bool("help", false, "show help")
	if err := g.Parse(args); err != nil {
		return errors.New("invalid global options; run workbench help")
	}
	args = g.Args()
	if *help || len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		a.help()
		return nil
	}
	command, args := args[0], args[1:]
	if command == "version" {
		fmt.Fprintln(a.Out, Version)
		return nil
	}
	if command == "path" {
		fmt.Fprintln(a.Out, filepath.Join(a.dir, "vault.age"))
		return nil
	}
	if command == "init" || command == "restore" {
		return a.initialize(command, args)
	}
	if command == "skill" {
		return a.skill(args)
	}
	if command == "install" {
		return a.install(args)
	}
	if command == "seal" {
		return a.seal(args)
	}
	if command == "unlock" {
		return a.unlock(args)
	}
	if command == "lock" {
		if len(args) != 0 {
			return errors.New("usage: lock")
		}
		if err := vault.Lock(a.dir, a.Session); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "Locked")
		return nil
	}
	s, err := a.open(a.Session)
	if err != nil {
		return err
	}
	switch command {
	case "list", "get", "require", "unset", "identity", "doctor", "reveal", "copy":
		return a.basic(s, command, args)
	case "set":
		return a.set(s, args)
	case "classify":
		return a.classify(s, args)
	case "exec":
		return a.runExec(s, args)
	case "use":
		return a.use(s, args)
	case "share":
		return a.share(s, args)
	case "import":
		return a.importShare(s, args)
	case "migrate":
		return a.migrate(s, args)
	case "backup":
		return a.backup(s, args)
	case "ui":
		f := flags("ui")
		noOpen := f.Bool("no-open", false, "do not open browser")
		timeout := f.Duration("timeout", 15*time.Minute, "inactivity timeout")
		pos, err := parse(f, args)
		if err != nil {
			return err
		}
		if len(pos) != 0 || *timeout < time.Minute || *timeout > time.Hour {
			return errors.New("usage: ui [--no-open] [--timeout 15m]; timeout must be 1m to 1h")
		}
		return ui.Serve(s, ui.Options{Out: a.Out, OpenBrowser: !*noOpen, Timeout: *timeout, Copy: a.Copy})
	default:
		return errors.New("unknown command; run workbench help")
	}
}

func (a *App) initialize(command string, args []string) error {
	f := flags(command)
	password := f.Bool("password", false, "protect identity with a passphrase")
	recoveryFile := f.String("backup-password-file", "", "private backup passphrase file")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	options := vault.InitOptions{UsePassword: *password || a.passwordFile != "" || runtime.GOOS != "darwin"}
	if command == "init" && len(pos) != 0 || command == "restore" && len(pos) != 1 {
		return errors.New("usage: init [--password] or restore BACKUP [--password]")
	}
	if command == "restore" {
		b, err := vault.ReadInput(pos[0], false)
		if err != nil {
			return err
		}
		pass, err := a.password(*recoveryFile, "Backup passphrase: ", false)
		if err != nil {
			return err
		}
		options.Identity, options.Entries, err = vault.Recover(b, pass)
		if err != nil {
			return err
		}
	}
	if options.UsePassword {
		options.Password, err = a.password(a.passwordFile, "New vault passphrase (at least 12 characters): ", true)
		if err != nil {
			return err
		}
	}
	s, err := vault.Init(a.dir, a.Ring, options)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Vault ready (%s). Create an encrypted recovery backup with workbench backup.\n", s.Backend())
	return nil
}

func (a *App) unlock(args []string) error {
	f := flags("unlock")
	ttl := f.Duration("ttl", 8*time.Hour, "how long commands without a terminal may open the vault")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 || *ttl < time.Minute || *ttl > 24*time.Hour {
		return errors.New("usage: unlock [--ttl 8h]; ttl must be 1m to 24h")
	}
	if a.passwordFile != "" {
		return errors.New("unlock needs the passphrase typed in a terminal, not --password-file")
	}
	// Never the cache: extending an unlock must require the passphrase again.
	s, err := a.open(nil)
	if err != nil {
		return err
	}
	if err := s.Unlock(a.Session, *ttl); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Unlocked for %s. Run wkb lock to end it earlier.\n", *ttl)
	return nil
}

func (a *App) basic(s *vault.Store, command string, args []string) error {
	if command == "identity" || command == "doctor" {
		if len(args) != 0 {
			return errors.New("this command takes no arguments")
		}
		if command == "identity" {
			fmt.Fprintln(a.Out, s.Identity())
		} else {
			fmt.Fprintf(a.Out, "Vault: valid and authenticated\nFiles: private\nBackend: %s\n", s.Backend())
		}
		return nil
	}
	f := flags(command)
	yes := f.Bool("yes", false, "confirm removal")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if command == "require" {
		if len(pos) == 0 {
			return errors.New("usage: require PATH...")
		}
		d, err := s.View()
		if err != nil {
			return err
		}
		missing := []string{}
		for _, raw := range pos {
			p, err := vault.Path(raw, true)
			if err != nil {
				return err
			}
			value, err := d.Tree(p, false)
			if err != nil || value == nil || value == "" {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			return errors.New("missing " + strings.Join(missing, " "))
		}
		return nil
	}
	if command == "list" && len(pos) == 0 {
		pos = []string{"."}
	}
	if len(pos) != 1 {
		return errors.New("command requires one PATH")
	}
	p, err := vault.Path(pos[0], command == "get" || command == "list")
	if err != nil {
		return err
	}
	if command == "unset" {
		if !*yes {
			confirmed, err := a.confirm("Remove " + p + " and its children?")
			if err != nil {
				return err
			}
			if !confirmed {
				return errors.New("cancelled")
			}
		}
		if err := s.Unset(p); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "Removed")
		return nil
	}
	d, err := s.View()
	if err != nil {
		return err
	}
	if command == "list" {
		if _, err := d.Tree(p, true); err != nil {
			return err
		}
		for _, item := range d.List(p) {
			classification := "public"
			if item.Secret {
				classification = "secret"
			}
			fmt.Fprintf(a.Out, "%s\t%s\t%s\n", item.Path, item.Type, classification)
		}
		return nil
	}
	if command == "get" {
		if e, exists := d.Entries[p]; exists {
			if e.Secret {
				fmt.Fprintln(a.Out, "***")
			} else {
				fmt.Fprintln(a.Out, vault.Display(e.Value))
			}
			return nil
		}
		value, err := d.Tree(p, true)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(value, "", "  ")
		fmt.Fprintln(a.Out, string(b))
		return nil
	}
	e, exists := d.Entries[p]
	if !exists {
		return errors.New("use an explicit scalar path")
	}
	if command == "copy" {
		if err := a.Copy(vault.Display(e.Value)); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "Copied")
		return nil
	}
	if command == "reveal" {
		out, ok := a.Out.(*os.File)
		if !ok || !term.IsTerminal(int(out.Fd())) {
			return errors.New("reveal requires an interactive terminal; use exec for automation")
		}
		confirmed, err := a.confirm("Reveal " + p + " in this terminal?")
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("cancelled")
		}
		fmt.Fprintln(a.Out, vault.Display(e.Value))
		return nil
	}
	return errors.New("unsupported command")
}

func (a *App) set(s *vault.Store, args []string) error {
	f := flags("set")
	public := f.Bool("public", false, "classify as public")
	stdin := f.Bool("stdin", false, "read value from stdin")
	jsonValue := f.Bool("json", false, "parse a JSON scalar")
	replace := f.Bool("replace", false, "confirm replacement")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: set PATH [--public] [--stdin] [--json] [--replace]; values are never accepted as arguments")
	}
	p, err := vault.Path(pos[0], false)
	if err != nil {
		return err
	}
	raw, err := a.readValue(*stdin, *jsonValue)
	if err != nil {
		return err
	}
	d, err := s.View()
	if err != nil {
		return err
	}
	if _, exists := d.Entries[p]; exists && !*replace {
		confirmed, err := a.confirm("Replace " + p + "?")
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("cancelled")
		}
		*replace = true
	}
	if err := s.Set(p, vault.Entry{Value: raw, Secret: !*public}, *replace); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Saved")
	return nil
}

func (a *App) runExec(s *vault.Store, args []string) error {
	split := -1
	for i, arg := range args {
		if arg == "--" {
			split = i
			break
		}
	}
	if split < 1 || split == len(args)-1 {
		return errors.New("usage: exec PATH=ENV_VAR ... -- COMMAND [ARGS]")
	}
	d, err := s.View()
	if err != nil {
		return err
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, mapping := range args[:split] {
		raw, variable, ok := strings.Cut(mapping, "=")
		if !ok || !validVariable(variable) || seen[variable] {
			return errors.New("mapping must be PATH=ENV_VAR with distinct valid variable names")
		}
		seen[variable] = true
		p, err := vault.Path(raw, false)
		if err != nil {
			return err
		}
		e, ok := d.Entries[p]
		if !ok {
			return errors.New("exec needs an existing scalar path")
		}
		values[variable] = vault.Display(e.Value)
	}
	return a.execute(args[split+1:], values)
}

func (a *App) execute(command []string, values map[string]string) error {
	env := os.Environ()
	for variable, value := range values {
		if !validVariable(variable) {
			return errors.New("invalid environment variable name")
		}
		if strings.ContainsRune(value, 0) {
			return errors.New("value cannot be represented in an environment variable")
		}
		filtered := env[:0]
		for _, existing := range env {
			if !strings.HasPrefix(existing, variable+"=") {
				filtered = append(filtered, existing)
			}
		}
		env = append(filtered, variable+"="+value)
	}
	binary, err := exec.LookPath(command[0])
	if err != nil {
		return errors.New("command not found")
	}
	if err := a.Exec(binary, command, env); err != nil {
		return errors.New("could not execute command")
	}
	return nil
}

func validVariable(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r != '_' && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (a *App) share(s *vault.Store, args []string) error {
	f := flags("share")
	to := f.String("to", "", "recipient public key")
	out := f.String("out", "", "new output file")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *to == "" {
		return errors.New("usage: share PATH --to PUBLIC_KEY [--out FILE]")
	}
	p, err := vault.Path(pos[0], false)
	if err != nil {
		return err
	}
	b, err := s.Share(p, *to)
	if err != nil {
		return err
	}
	return a.output(b, *out)
}

func (a *App) input(path string) ([]byte, error) {
	if path != "-" {
		return vault.ReadInput(path, false)
	}
	b, err := io.ReadAll(io.LimitReader(a.In, vault.MaxBlob+1))
	if err != nil || len(b) > vault.MaxBlob {
		return nil, errors.New("input is too large or unreadable")
	}
	return b, nil
}

func (a *App) output(b []byte, path string) error {
	if path != "" {
		if err := vault.WriteOutput(path, b); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "Encrypted file saved")
		return nil
	}
	_, err := a.Out.Write(b)
	return err
}

func (a *App) importShare(s *vault.Store, args []string) error {
	f := flags("import")
	as := f.String("as", "", "local destination path")
	yes := f.Bool("yes", false, "confirm import")
	replace := f.Bool("replace", false, "confirm replacement")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: import FILE|- [--as PATH] [--yes] [--replace]")
	}
	b, err := a.input(pos[0])
	if err != nil {
		return err
	}
	share, err := s.InspectShare(b)
	if err != nil {
		return err
	}
	p := share.Path
	if *as != "" {
		p, err = vault.Path(*as, false)
		if err != nil {
			return err
		}
	}
	if !*yes {
		confirmed, err := a.confirm("Import " + p + "? Sender identity is not authenticated")
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("cancelled")
		}
	}
	if err := s.Set(p, share.Entry, *replace); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Imported")
	return nil
}

type paths []string

func (p *paths) String() string { return strings.Join(*p, ",") }
func (p *paths) Set(s string) error {
	normalized, err := vault.Path(s, false)
	if err != nil {
		return err
	}
	*p = append(*p, normalized)
	return nil
}

func (a *App) migrate(s *vault.Store, args []string) error {
	f := flags("migrate")
	yes := f.Bool("yes", false, "confirm migration")
	replace := f.Bool("replace", false, "confirm conflicts")
	var publics paths
	f.Var(&publics, "public", "explicit public path; repeatable")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: migrate PRIVATE_YAML [--public PATH] [--yes] [--replace]")
	}
	b, err := vault.ReadInput(pos[0], true)
	if err != nil {
		return err
	}
	var data map[string]any
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	if err := decoder.Decode(&data); err != nil {
		return errors.New("invalid YAML; no values were imported")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("YAML must contain exactly one document")
	}
	public := map[string]bool{}
	for _, p := range publics {
		public[p] = true
	}
	entries, err := vault.Flatten(data, public)
	if err != nil {
		return err
	}
	for _, prefix := range publics {
		matched := false
		for p := range entries {
			if vault.Contains(prefix, p) {
				matched = true
			}
		}
		if !matched {
			return errors.New("a requested public path was not found; migration cancelled")
		}
	}
	if !*yes {
		confirmed, err := a.confirm(fmt.Sprintf("Import %d values? All are secret except explicitly public paths. The source YAML stays unchanged", len(entries)))
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("cancelled")
		}
	}
	err = s.Update(func(d *vault.Document) error {
		for p, e := range entries {
			if _, exists := d.Entries[p]; exists && !*replace {
				return errors.New("migration conflicts with existing paths; no values were imported")
			}
			d.Entries[p] = e
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Imported %d values. Source YAML unchanged and still contains plaintext secrets.\n", len(entries))
	return nil
}

func (a *App) backup(s *vault.Store, args []string) error {
	f := flags("backup")
	out := f.String("out", "", "new output file")
	passwordFile := f.String("backup-password-file", "", "private recovery passphrase file")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 || *out == "" {
		return errors.New("usage: backup --out FILE [--backup-password-file FILE]")
	}
	pass, err := a.password(*passwordFile, "New backup passphrase (at least 12 characters): ", true)
	if err != nil {
		return err
	}
	b, err := s.Backup(pass)
	if err != nil {
		return err
	}
	return a.output(b, *out)
}

func Clipboard(value string) error {
	var command []string
	if runtime.GOOS == "darwin" {
		command = []string{"/usr/bin/pbcopy"}
	} else {
		for _, candidate := range [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}} {
			if _, err := exec.LookPath(candidate[0]); err == nil {
				command = candidate
				break
			}
		}
	}
	if len(command) == 0 {
		return errors.New("no clipboard tool found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = strings.NewReader(value)
	if err := cmd.Run(); err != nil {
		return errors.New("clipboard copy failed")
	}
	return nil
}

func (a *App) help() {
	fmt.Fprintln(a.Out, `Workbench - encrypted local configuration

Usage: workbench [--dir DIR] [--password-file FILE] COMMAND

  init [--password]                  Create a vault, never overwrite one
  install [--dir BIN] [--replace]    Install wkb in ~/.local/bin
  list [PREFIX]                      List paths, types and classifications
  get PATH                           Read public values; mask every secret
  set PATH [--public] [--stdin]       Prompt hidden, or read stdin; --replace confirms update
  classify PATH --public|--secret    Change visibility without replacing the value
  unset PATH [--yes]                 Remove a path and its children
  copy PATH                          Copy a scalar without printing it
  reveal PATH                        Explicit terminal-only disclosure
  require PATH...                    Check required scalar values
  exec PATH=ENV ... -- CMD [ARGS]     Inject values into a child process
  seal [--to KEY] [--stdin]          Encrypt a hidden value without saving it
  use FILE|- --env ENV -- CMD        Use an encrypted packet without importing it
  ui [--no-open] [--timeout 15m]      Authenticated local browser interface
  identity                           Show your public age receiving key
  share PATH --to KEY [--out FILE]   Encrypt one value for a recipient
  import FILE|- [--as PATH] [--yes]   Import data; --replace confirms conflicts
  migrate YAML [--public PATH]       Import private YAML; --yes/--replace for automation
  backup --out FILE                  Passphrase-encrypted recovery backup
  unlock [--ttl 8h]                  Linux: let commands without a terminal open the vault
  lock                               End an unlock before its ttl
  restore BACKUP [--password]        Restore identity and data into a NEW vault
  doctor                             Authenticate vault and check permissions
  path                               Show encrypted vault location
  version                            Show version
  skill install [--agent NAME]       Install the bundled Agent Skill; --global/--dir DIR

Backup/restore accept --backup-password-file FILE. Passphrase files must be
private regular files. There is no remote service and no plaintext fallback.`)
}
