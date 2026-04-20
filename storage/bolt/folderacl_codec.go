package bolt

import (
	"encoding/json"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
)

// marshalEntries encodes the ACL entry slice to a compact JSON blob
// for storage in a single storm column. Kept in its own file so the
// serialization format is easy to audit as a surface distinct from
// the storage schema itself.
func marshalEntries(entries []folderacl.Entry) (string, error) {
	if len(entries) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalEntries reverses marshalEntries. Accepts empty + nil
// strings (legacy rows written before this field existed) as an
// empty slice rather than an error so migrations stay painless.
func unmarshalEntries(blob string) ([]folderacl.Entry, error) {
	if blob == "" || blob == "null" {
		return nil, nil
	}
	var entries []folderacl.Entry
	if err := json.Unmarshal([]byte(blob), &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
