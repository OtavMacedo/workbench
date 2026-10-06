package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const Version = 1
const MaxBlob = 8 << 20

var pathPattern = regexp.MustCompile(`^(\.[A-Za-z0-9_-]+|\[(0|[1-9][0-9]*)\])+$`)
var partPattern = regexp.MustCompile(`\.([A-Za-z0-9_-]+)|\[([0-9]+)\]`)

type Entry struct {
	Value  json.RawMessage `json:"value"`
	Secret bool            `json:"secret"`
}

func (e *Entry) UnmarshalJSON(b []byte) error {
	var raw struct {
		Value  json.RawMessage `json:"value"`
		Secret *bool           `json:"secret"`
	}
	if err := decode(b, &raw); err != nil || raw.Value == nil || raw.Secret == nil {
		return errors.New("entry requires a value and explicit secret classification")
	}
	e.Value, e.Secret = raw.Value, *raw.Secret
	return nil
}

type Document struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

type Info struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Secret bool   `json:"secret"`
}

func Path(raw string, root bool) (string, error) {
	p := strings.TrimSpace(raw)
	if p != "" && !strings.HasPrefix(p, ".") {
		p = "." + p
	}
	if root && p == "." {
		return p, nil
	}
	if len(p) > 512 || !pathPattern.MatchString(p) || strings.HasPrefix(p, ".[") {
		return "", errors.New("invalid path; use .service.token or .services[0].token")
	}
	for _, m := range partPattern.FindAllStringSubmatch(p, -1) {
		if m[2] != "" {
			n, err := strconv.Atoi(m[2])
			if err != nil || n > 10000 {
				return "", errors.New("array index is too large")
			}
		}
	}
	return p, nil
}

func Scalar(value json.RawMessage) error {
	var v any
	if len(value) > 1<<20 || json.Unmarshal(value, &v) != nil {
		return errors.New("value must be valid JSON of at most 1 MiB")
	}
	switch v.(type) {
	case map[string]any, []any:
		return errors.New("value must be a scalar; use separate paths for objects and arrays")
	}
	return nil
}

func Type(value json.RawMessage) string {
	var v any
	_ = json.Unmarshal(value, &v)
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	default:
		return "string"
	}
}

func Display(value json.RawMessage) string {
	var s string
	if json.Unmarshal(value, &s) == nil {
		return s
	}
	return string(value)
}

func Contains(prefix, p string) bool {
	return prefix == "." || prefix == p || strings.HasPrefix(p, prefix+".") || strings.HasPrefix(p, prefix+"[")
}

func (d Document) Validate() error {
	if d.Version != Version || d.Entries == nil || len(d.Entries) > 10000 {
		return errors.New("invalid or unsupported vault document")
	}
	paths := make([]string, 0, len(d.Entries))
	for p, e := range d.Entries {
		if n, err := Path(p, false); err != nil || n != p {
			return errors.New("invalid entry path")
		}
		if err := Scalar(e.Value); err != nil {
			return err
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for i := 1; i < len(paths); i++ {
		if Contains(paths[i-1], paths[i]) {
			return errors.New("a scalar path cannot contain other entries")
		}
	}
	_, err := d.Tree(".", true)
	return err
}

func (d Document) List(prefix string) []Info {
	items := []Info{}
	for p, e := range d.Entries {
		if Contains(prefix, p) {
			items = append(items, Info{p, Type(e.Value), e.Secret})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

type node struct {
	value    any
	leaf     bool
	children map[string]*node
	array    bool
}

func (d Document) Tree(prefix string, masked bool) (any, error) {
	root := &node{children: map[string]*node{}}
	for p, e := range d.Entries {
		current := root
		for _, m := range partPattern.FindAllStringSubmatch(p, -1) {
			if current.leaf {
				return nil, errors.New("a scalar path cannot contain other entries")
			}
			array := m[2] != ""
			if len(current.children) > 0 && current.array != array {
				return nil, errors.New("a path cannot be both object and array")
			}
			current.array = array
			key := m[1]
			if array {
				key = m[2]
			}
			if current.children[key] == nil {
				current.children[key] = &node{children: map[string]*node{}}
			}
			current = current.children[key]
		}
		if len(current.children) != 0 {
			return nil, errors.New("a scalar path cannot contain other entries")
		}
		current.leaf = true
		if masked && e.Secret {
			current.value = "***"
		} else {
			decoder := json.NewDecoder(strings.NewReader(string(e.Value)))
			decoder.UseNumber()
			if err := decoder.Decode(&current.value); err != nil {
				return nil, errors.New("invalid value")
			}
		}
	}
	if err := root.validate(); err != nil {
		return nil, err
	}
	selected := root
	if prefix != "." {
		for _, m := range partPattern.FindAllStringSubmatch(prefix, -1) {
			if selected.leaf || selected.array != (m[2] != "") {
				return nil, errors.New("path not found")
			}
			key := m[1]
			if m[2] != "" {
				key = m[2]
			}
			selected = selected.children[key]
			if selected == nil {
				return nil, errors.New("path not found")
			}
		}
	}
	return selected.materialize(), nil
}

func (n *node) validate() error {
	if n.array {
		for i := 0; i < len(n.children); i++ {
			if n.children[strconv.Itoa(i)] == nil {
				return errors.New("array indices must be contiguous starting at zero")
			}
		}
	}
	for _, child := range n.children {
		if err := child.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) materialize() any {
	if n.leaf {
		return n.value
	}
	if n.array {
		length := 0
		for key := range n.children {
			i, _ := strconv.Atoi(key)
			if i >= length {
				length = i + 1
			}
		}
		result := make([]any, length)
		for key, child := range n.children {
			i, _ := strconv.Atoi(key)
			result[i] = child.materialize()
		}
		return result
	}
	result := map[string]any{}
	for key, child := range n.children {
		result[key] = child.materialize()
	}
	return result
}

func Flatten(value any, public map[string]bool) (map[string]Entry, error) {
	entries := map[string]Entry{}
	var walk func(any, string) error
	walk = func(v any, p string) error {
		switch item := v.(type) {
		case map[string]any:
			if len(item) == 0 && p != "." {
				return errors.New("empty objects are not supported; no data was imported")
			}
			for key, child := range item {
				next := p + "." + key
				if p == "." {
					next = "." + key
				}
				if err := walk(child, next); err != nil {
					return err
				}
			}
		case []any:
			if len(item) == 0 {
				return errors.New("empty arrays are not supported; no data was imported")
			}
			for index, child := range item {
				if err := walk(child, fmt.Sprintf("%s[%d]", p, index)); err != nil {
					return err
				}
			}
		default:
			normalized, err := Path(p, false)
			if err != nil || normalized != p {
				return errors.New("YAML contains an unsupported path; no data was imported")
			}
			value, err := json.Marshal(v)
			if err != nil {
				return errors.New("YAML contains an unsupported value")
			}
			secret := true
			for prefix := range public {
				if Contains(prefix, p) {
					secret = false
				}
			}
			entries[p] = Entry{value, secret}
		}
		return nil
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("YAML must contain an object at the root")
	}
	if err := walk(value, "."); err != nil {
		return nil, err
	}
	d := Document{Version, entries}
	return entries, d.Validate()
}
