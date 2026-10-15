package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/pedroloch/workbench/internal/keyring"
)

type Metadata struct {
	Version   int    `json:"version"`
	Backend   string `json:"backend"`
	Account   string `json:"account"`
	Recipient string `json:"recipient"`
}

type Store struct {
	Dir      string
	metadata Metadata
	identity *age.X25519Identity
}

type InitOptions struct {
	Password    string
	UsePassword bool
	Identity    *age.X25519Identity
	Entries     map[string]Entry
}

func decode(b []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid document")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("invalid document")
	}
	return nil
}

func encrypt(b []byte, recipient age.Recipient, armored bool) ([]byte, error) {
	var buffer bytes.Buffer
	var output io.Writer = &buffer
	var armorWriter io.WriteCloser
	if armored {
		armorWriter = armor.NewWriter(&buffer)
		output = armorWriter
	}
	w, err := age.Encrypt(output, recipient)
	if err != nil {
		return nil, errors.New("encryption failed")
	}
	if _, err := w.Write(b); err != nil {
		return nil, errors.New("encryption failed")
	}
	if err := w.Close(); err != nil {
		return nil, errors.New("encryption failed")
	}
	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return nil, errors.New("encryption failed")
		}
	}
	return buffer.Bytes(), nil
}

func decrypt(b []byte, identity age.Identity) ([]byte, error) {
	if len(b) > MaxBlob {
		return nil, errors.New("cannot decrypt: oversized data")
	}
	var input io.Reader = bytes.NewReader(b)
	trimmed := bytes.TrimSpace(b)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		input = armor.NewReader(bytes.NewReader(trimmed))
	} else if !bytes.HasPrefix(b, []byte("age-encryption.org/v1\n")) {
		// Accept the Base64 body copied from an armored packet, with or without
		// line wrapping. Decoding changes representation, not authentication.
		compact := bytes.Map(func(r rune) rune {
			switch r {
			case ' ', '\t', '\r', '\n':
				return -1
			default:
				return r
			}
		}, trimmed)
		encoding := base64.StdEncoding.Strict()
		if !bytes.ContainsRune(compact, '=') {
			encoding = base64.RawStdEncoding.Strict()
		}
		decoded, err := encoding.DecodeString(string(compact))
		if err != nil || !bytes.HasPrefix(decoded, []byte("age-encryption.org/v1\n")) {
			return nil, errors.New("cannot decrypt: invalid encrypted packet format")
		}
		input = bytes.NewReader(decoded)
	}
	r, err := age.Decrypt(input, identity)
	if err != nil {
		return nil, errors.New("cannot decrypt: wrong key, password, recipient or corrupted data")
	}
	clear, err := io.ReadAll(io.LimitReader(r, MaxBlob+1))
	if err != nil || len(clear) > MaxBlob {
		return nil, errors.New("cannot decrypt: corrupted or oversized data")
	}
	return clear, nil
}

func passwordRecipient(password string) (age.Recipient, error) {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 {
		return nil, errors.New("use a passphrase of at least 12 characters")
	}
	r, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, errors.New("invalid passphrase")
	}
	return r, nil
}

func passwordIdentity(password string) (age.Identity, error) {
	i, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, errors.New("invalid passphrase")
	}
	i.SetMaxWorkFactor(18)
	return i, nil
}

func Init(dir string, ring keyring.Backend, options InitOptions) (*Store, error) {
	entries := options.Entries
	if entries == nil {
		entries = map[string]Entry{}
	}
	d := Document{Version, entries}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	root, err := openDirectory(dir, true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	release, err := lock(root)
	if err != nil {
		return nil, err
	}
	defer release()
	for _, name := range []string{"meta.json", "vault.age", "identity.age"} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("vault files already exist; init will not overwrite them")
		}
	}
	identity := options.Identity
	if identity == nil {
		identity, err = age.GenerateX25519Identity()
		if err != nil {
			return nil, errors.New("cannot generate vault identity")
		}
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, errors.New("cannot generate vault identifier")
	}
	m := Metadata{Version, "keychain", hex.EncodeToString(id), identity.Recipient().String()}
	var sealedIdentity []byte
	if options.UsePassword {
		m.Backend = "password"
		r, err := passwordRecipient(options.Password)
		if err != nil {
			return nil, err
		}
		sealedIdentity, err = encrypt([]byte(identity.String()), r, false)
		if err != nil {
			return nil, err
		}
	} else {
		if err := ring.Set(m.Account, identity.String()); err != nil {
			return nil, err
		}
	}
	committed := false
	defer func() {
		if !committed {
			_ = root.Remove("vault.age")
			_ = root.Remove("identity.age")
			_ = root.Remove("meta.json")
			if m.Backend == "keychain" {
				_ = ring.Delete(m.Account)
			}
		}
	}()
	if m.Backend == "password" {
		if err := writeAtomic(root, "identity.age", sealedIdentity); err != nil {
			return nil, err
		}
	}
	clear, err := json.Marshal(d)
	if err != nil {
		return nil, errors.New("cannot encode vault")
	}
	sealed, err := encrypt(clear, identity.Recipient(), false)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(root, "vault.age", sealed); err != nil {
		return nil, err
	}
	meta, _ := json.MarshalIndent(m, "", "  ")
	if err := writeAtomic(root, "meta.json", meta); err != nil {
		return nil, err
	}
	committed = true
	return &Store{dir, m, identity}, nil
}

func readMetadata(root *os.Root) (Metadata, error) {
	b, err := readPrivate(root, "meta.json")
	if err != nil {
		return Metadata{}, err
	}
	var m Metadata
	if err := decode(b, &m); err != nil || m.Version != Version || len(m.Account) != 32 {
		return Metadata{}, errors.New("invalid vault metadata")
	}
	if _, err := hex.DecodeString(m.Account); err != nil {
		return Metadata{}, errors.New("invalid vault metadata")
	}
	return m, nil
}

func unsealIdentity(root *os.Root, password func() (string, error)) (string, error) {
	sealed, err := readPrivate(root, "identity.age")
	if err != nil {
		return "", err
	}
	pass, err := password()
	if err != nil {
		return "", err
	}
	i, err := passwordIdentity(pass)
	if err != nil {
		return "", err
	}
	clear, err := decrypt(sealed, i)
	if err != nil {
		return "", err
	}
	return string(clear), nil
}

// Open reads a passphrase vault's identity from cache when unlocked; a nil
// cache always asks for the passphrase.
func Open(dir string, ring keyring.Backend, cache keyring.Cache, password func() (string, error)) (*Store, error) {
	root, err := openDirectory(dir, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	m, err := readMetadata(root)
	if err != nil {
		return nil, err
	}
	var raw string
	switch m.Backend {
	case "keychain":
		raw, err = ring.Get(m.Account)
	case "password":
		err = keyring.ErrLocked
		if cache != nil {
			raw, err = cache.Get(m.Account)
		}
		if err != nil {
			raw, err = unsealIdentity(root, password)
		}
	default:
		return nil, errors.New("unsupported vault backend")
	}
	if err != nil {
		return nil, err
	}
	identity, err := age.ParseX25519Identity(raw)
	if err != nil || identity.Recipient().String() != m.Recipient {
		return nil, errors.New("vault identity does not match metadata")
	}
	s := &Store{dir, m, identity}
	if _, err := s.read(root); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Identity() string { return s.metadata.Recipient }
func (s *Store) Backend() string  { return s.metadata.Backend }

func (s *Store) Unlock(cache keyring.Cache, ttl time.Duration) error {
	if s.metadata.Backend != "password" {
		return errors.New("unlock applies only to passphrase vaults")
	}
	return cache.Put(s.metadata.Account, s.identity.String(), ttl)
}

func Lock(dir string, cache keyring.Cache) error {
	root, err := openDirectory(dir, false)
	if err != nil {
		return err
	}
	defer root.Close()
	m, err := readMetadata(root)
	if err != nil {
		return err
	}
	if m.Backend != "password" {
		return errors.New("lock applies only to passphrase vaults")
	}
	return cache.Delete(m.Account)
}

func (s *Store) read(root *os.Root) (Document, error) {
	b, err := readPrivate(root, "vault.age")
	if err != nil {
		return Document{}, err
	}
	clear, err := decrypt(b, s.identity)
	if err != nil {
		return Document{}, err
	}
	var d Document
	if err := decode(clear, &d); err != nil {
		return Document{}, errors.New("invalid vault document")
	}
	if err := d.Validate(); err != nil {
		return Document{}, err
	}
	return d, nil
}

func (s *Store) View() (Document, error) {
	root, err := openDirectory(s.Dir, false)
	if err != nil {
		return Document{}, err
	}
	defer root.Close()
	return s.read(root)
}

func (s *Store) Update(change func(*Document) error) error {
	root, err := openDirectory(s.Dir, false)
	if err != nil {
		return err
	}
	defer root.Close()
	release, err := lock(root)
	if err != nil {
		return err
	}
	defer release()
	d, err := s.read(root)
	if err != nil {
		return err
	}
	if err := change(&d); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return err
	}
	clear, err := json.Marshal(d)
	if err != nil {
		return errors.New("cannot encode vault")
	}
	sealed, err := encrypt(clear, s.identity.Recipient(), false)
	if err != nil {
		return err
	}
	return writeAtomic(root, "vault.age", sealed)
}

func (s *Store) Set(p string, e Entry, replace bool) error {
	if normalized, err := Path(p, false); err != nil || normalized != p {
		return errors.New("invalid path")
	}
	if err := Scalar(e.Value); err != nil {
		return err
	}
	return s.Update(func(d *Document) error {
		if _, exists := d.Entries[p]; exists && !replace {
			return errors.New("path exists; explicitly confirm replacement")
		}
		d.Entries[p] = e
		return nil
	})
}

func (s *Store) Unset(p string) error {
	return s.Update(func(d *Document) error {
		found := false
		for key := range d.Entries {
			if Contains(p, key) {
				delete(d.Entries, key)
				found = true
			}
		}
		if !found {
			return errors.New("path not found")
		}
		return nil
	})
}

// Classify changes visibility while preserving the current value under the writer lock.
func (s *Store) Classify(p string, secret bool) error {
	return s.Update(func(d *Document) error {
		e, ok := d.Entries[p]
		if !ok {
			return errors.New("classification needs an existing scalar path")
		}
		e.Secret = secret
		d.Entries[p] = e
		return nil
	})
}

type Share struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Path    string `json:"path"`
	Entry   Entry  `json:"entry"`
}

func (s *Store) Share(p, to string) ([]byte, error) {
	d, err := s.View()
	if err != nil {
		return nil, err
	}
	e, ok := d.Entries[p]
	if !ok {
		return nil, errors.New("share needs an explicit scalar path")
	}
	return Seal(p, e, to)
}

// Seal encrypts a supplied value without opening or updating a vault.
func Seal(p string, e Entry, to string) ([]byte, error) {
	if normalized, err := Path(p, false); err != nil || normalized != p {
		return nil, errors.New("invalid share path")
	}
	if err := Scalar(e.Value); err != nil {
		return nil, err
	}
	r, err := age.ParseX25519Recipient(to)
	if err != nil {
		return nil, errors.New("invalid age recipient public key")
	}
	b, _ := json.Marshal(Share{"workbench-share", Version, p, e})
	return encrypt(b, r, true)
}

func (s *Store) InspectShare(b []byte) (Share, error) {
	if len(b) > MaxBlob {
		return Share{}, errors.New("share is too large")
	}
	clear, err := decrypt(b, s.identity)
	if err != nil {
		return Share{}, err
	}
	var share Share
	if err := decode(clear, &share); err != nil || share.Format != "workbench-share" || share.Version != Version {
		return Share{}, errors.New("invalid or unsupported share")
	}
	if p, err := Path(share.Path, false); err != nil || p != share.Path {
		return Share{}, errors.New("invalid share path")
	}
	if err := Scalar(share.Entry.Value); err != nil {
		return Share{}, err
	}
	return share, nil
}

type Recovery struct {
	Format   string   `json:"format"`
	Version  int      `json:"version"`
	Identity string   `json:"identity"`
	Document Document `json:"document"`
}

func (s *Store) Backup(password string) ([]byte, error) {
	r, err := passwordRecipient(password)
	if err != nil {
		return nil, err
	}
	d, err := s.View()
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(Recovery{"workbench-recovery", Version, s.identity.String(), d})
	return encrypt(b, r, true)
}

func Recover(b []byte, password string) (*age.X25519Identity, map[string]Entry, error) {
	i, err := passwordIdentity(password)
	if err != nil {
		return nil, nil, err
	}
	clear, err := decrypt(b, i)
	if err != nil {
		return nil, nil, err
	}
	var r Recovery
	if err := decode(clear, &r); err != nil || r.Format != "workbench-recovery" || r.Version != Version {
		return nil, nil, errors.New("invalid recovery backup")
	}
	if err := r.Document.Validate(); err != nil {
		return nil, nil, err
	}
	identity, err := age.ParseX25519Identity(r.Identity)
	if err != nil {
		return nil, nil, errors.New("invalid recovery identity")
	}
	return identity, r.Document.Entries, nil
}
