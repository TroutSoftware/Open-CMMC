// Package enclave is the enclave-side complement of share/daemon. It
// rewraps a file's plaintext under a fresh per-share DEK protected by
// Argon2id(passphrase, salt, server-pepper), and ships the (metadata
// + ciphertext) pair to the DMZ daemon via the mTLS back-channel.
//
// The KEK never leaves the enclave. The share daemon only ever sees
// the passphrase-wrapped DEK and the blob encrypted with that DEK —
// it cannot derive plaintext without the passphrase.
package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/filebrowser/filebrowser/v2/share/daemon"
)

// RewrapParams captures everything the enclave needs to generate a
// share artifact from a file it already has plaintext access to.
type RewrapParams struct {
	Plaintext    []byte
	Filename     string
	ContentType  string
	CUIMark      string
	SenderUserID string
	RecipientEmail string // hashed with pepper before storage
	TTL          time.Duration
	MaxDownloads int
	MaxFailures  int
	Passphrase   string // out-of-band shared with recipient
	CorrelationID string
}

// Argon2Params is the enclave's current tuning for the passphrase
// KDF. Kept as a variable so operators can bump time/memory without
// breaking older shares (parameters travel with the metadata).
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultArgon2Params are the OWASP-recommended-ish defaults for
// server-side Argon2id. Tune up as hardware gets faster. At
// m=64MiB/t=3/p=4 each derive takes roughly 100ms on modern CPUs —
// fast enough for a legitimate recipient, painful enough to make a
// brute-force against a stolen DMZ disk economically uninteresting.
var DefaultArgon2Params = Argon2Params{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 4,
}

// Artifact is what Rewrap produces: the Metadata the daemon will
// persist, plus the ciphertext blob it stores alongside.
type Artifact struct {
	Meta daemon.Metadata
	Blob []byte
}

// Rewrap generates a fresh DEK, encrypts the plaintext under it,
// wraps the DEK under Argon2id(passphrase || pepper, salt), and
// packages everything into an Artifact ready for pusher.Push.
//
// pepperID identifies the pepper the daemon is currently configured
// with; it is echoed in Metadata.Wrap.PepperID so future pepper
// rotation can be detected (a share whose PepperID no longer matches
// the daemon's active pepper is unrecoverable, by design).
func Rewrap(p RewrapParams, pepper []byte, pepperID string, params Argon2Params) (*Artifact, error) {
	if err := validateRewrapParams(p); err != nil {
		return nil, err
	}
	if len(pepper) < 32 {
		return nil, errors.New("rewrap: pepper must be at least 32 bytes")
	}

	// Per-share DEK: 32 random bytes, used exactly once.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("rewrap: dek: %w", err)
	}
	// Per-share blob nonce.
	blobNonce := make([]byte, 12)
	if _, err := rand.Read(blobNonce); err != nil {
		return nil, fmt.Errorf("rewrap: blob nonce: %w", err)
	}
	blobBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("rewrap: blob cipher: %w", err)
	}
	blobGCM, err := cipher.NewGCM(blobBlock)
	if err != nil {
		return nil, fmt.Errorf("rewrap: blob gcm: %w", err)
	}
	blob := blobGCM.Seal(nil, blobNonce, p.Plaintext, nil)

	// Per-share salt for the Argon2 derive.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("rewrap: salt: %w", err)
	}
	// Key-wrapping key from (passphrase || pepper) + salt.
	material := make([]byte, 0, len(p.Passphrase)+len(pepper))
	material = append(material, []byte(p.Passphrase)...)
	material = append(material, pepper...)
	kwk := argon2.IDKey(material, salt, params.Time, params.Memory, params.Threads, 32)

	wrapBlock, err := aes.NewCipher(kwk)
	if err != nil {
		return nil, fmt.Errorf("rewrap: kwk cipher: %w", err)
	}
	wrapGCM, err := cipher.NewGCM(wrapBlock)
	if err != nil {
		return nil, fmt.Errorf("rewrap: kwk gcm: %w", err)
	}
	wrapNonce := make([]byte, 12)
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("rewrap: wrap nonce: %w", err)
	}
	wrapped := wrapGCM.Seal(nil, wrapNonce, dek, nil)

	// Share ID.
	id, err := daemon.NewID()
	if err != nil {
		return nil, fmt.Errorf("rewrap: id: %w", err)
	}

	now := time.Now().UTC()
	meta := daemon.Metadata{
		ID:                 id,
		CreatedAt:          now,
		ExpiresAt:          now.Add(p.TTL),
		MaxDownloads:       p.MaxDownloads,
		DownloadsRemaining: p.MaxDownloads,
		MaxFailures:        p.MaxFailures,
		CUIMark:            p.CUIMark,
		SenderUserID:       p.SenderUserID,
		RecipientEmailHash: HashEmail(p.RecipientEmail, pepper),
		CorrelationID:      p.CorrelationID,
		Filename:           p.Filename,
		ContentType:        p.ContentType,
		BlobSize:           int64(len(blob)),
		Wrap: daemon.WrapParams{
			KDF:        "argon2id",
			Argon2Time: params.Time,
			Argon2Mem:  params.Memory,
			Argon2Par:  params.Threads,
			SaltB64:    base64.StdEncoding.EncodeToString(salt),
			PepperID:   pepperID,
			WrappedDEK: base64.StdEncoding.EncodeToString(append(wrapNonce, wrapped...)),
			BlobNonce:  base64.StdEncoding.EncodeToString(blobNonce),
			BlobAEAD:   "aes-256-gcm",
		},
	}

	// Best-effort: scrub the DEK and KWK from memory. Go's GC will
	// collect them eventually, but clearing now reduces the window
	// in which a core dump / swap page leaks them.
	for i := range dek {
		dek[i] = 0
	}
	for i := range kwk {
		kwk[i] = 0
	}

	return &Artifact{Meta: meta, Blob: blob}, nil
}

func validateRewrapParams(p RewrapParams) error {
	switch {
	case len(p.Plaintext) == 0:
		return errors.New("rewrap: empty plaintext")
	case p.Passphrase == "":
		return errors.New("rewrap: empty passphrase")
	case p.TTL <= 0:
		return errors.New("rewrap: TTL must be positive")
	case p.MaxDownloads <= 0:
		return errors.New("rewrap: MaxDownloads must be positive")
	case p.MaxFailures <= 0:
		return errors.New("rewrap: MaxFailures must be positive")
	case p.SenderUserID == "":
		return errors.New("rewrap: SenderUserID required")
	case p.RecipientEmail == "":
		return errors.New("rewrap: RecipientEmail required")
	}
	// CUI-marking policy: SP-ITAR and SP-NOFORN categories must
	// NOT leave the enclave via the share daemon. Enforced here so
	// a misconfigured UI or a future caller can't accidentally
	// bypass the rule.
	mark := strings.ToUpper(strings.TrimSpace(p.CUIMark))
	if mark == "SP-ITAR" || mark == "CUI//SP-ITAR" || mark == "SP-NOFORN" || mark == "CUI//SP-NOFORN" {
		return fmt.Errorf("rewrap: refusing to export %s via share daemon", mark)
	}
	return nil
}

// HashEmail hashes recipient email for storage in Metadata. The
// daemon never sees the plaintext email. Lowercased + trimmed before
// hashing so capitalization variants collapse to the same bucket.
func HashEmail(email string, pepper []byte) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	h.Write(pepper)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GeneratePassphrase returns a human-typeable 6-word passphrase from
// a small wordlist. Used when the operator chooses "generate"
// instead of entering a custom passphrase. ~77 bits of entropy
// (13 bits * 6 words); paired with per-share Argon2 and the N-tries
// auto-burn this is comfortably above the guess-budget an attacker
// could realistically spend.
func GeneratePassphrase() (string, error) {
	words := make([]string, 6)
	for i := range words {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("passphrase: rand: %w", err)
		}
		idx := (uint16(b[0])<<8 | uint16(b[1])) % uint16(len(wordlist))
		words[i] = wordlist[idx]
	}
	return strings.Join(words, "-"), nil
}

// wordlist is 8192 entries (13 bits each). For a first cut I use a
// short curated slice and pad with hex-style filler so unit tests
// can run without a megabyte wordlist checked in. Production should
// swap in the EFF long wordlist (7776 entries) or similar.
var wordlist = func() []string {
	base := []string{
		"able", "acid", "aged", "airy", "alert", "allow", "alpha", "amber",
		"anchor", "angel", "anvil", "apple", "arbor", "arena", "arrow", "arid",
		"asset", "astra", "atlas", "atom", "audio", "avenue", "axiom", "azure",
		"bagel", "balsa", "bamboo", "banjo", "basalt", "basin", "bayou", "beach",
		"beacon", "beaker", "beetle", "bevel", "birch", "bison", "blaze", "blend",
		"blue", "bolt", "bond", "bore", "borax", "brass", "brave", "bread",
		"briar", "brick", "bridge", "brief", "brisk", "broth", "brown", "burst",
		"cabin", "cable", "cacti", "camp", "candy", "canoe", "canvas", "canyon",
		"carat", "cargo", "carob", "cedar", "celer", "chant", "chime", "chord",
		"cider", "cinder", "civet", "cliff", "cloak", "clock", "cloud", "clover",
		"coast", "cobalt", "comet", "copper", "coral", "cotton", "cove", "cozy",
		"crane", "crater", "creek", "crest", "croft", "crown", "crumb", "crust",
		"cyan", "dawn", "deck", "delta", "depot", "derby", "desert", "dial",
		"diner", "ditch", "dock", "dove", "drift", "drum", "dune", "dust",
		"eagle", "earth", "easel", "ebony", "echo", "eddy", "eel", "egret",
		"elder", "elk", "elm", "ember", "enamel", "epic", "ether", "eve",
		"fable", "fairy", "falcon", "falls", "fang", "farm", "fawn", "felt",
		"fern", "field", "finch", "fjord", "flame", "flank", "flare", "flax",
		"fleet", "flint", "float", "flock", "flour", "flume", "foam", "foil",
		"font", "forge", "forum", "fox", "free", "fresh", "frog", "frost",
		"gale", "gap", "garb", "garnet", "gauge", "gecko", "gem", "giant",
		"ginger", "glade", "glass", "glider", "globe", "glow", "gold", "goose",
		"gorge", "grain", "grape", "graph", "grass", "green", "grid", "grist",
		"grove", "guild", "gull", "gum", "gust", "gyro", "haiku", "hale",
		"halo", "hammer", "harbor", "hare", "harp", "harvest", "hatch", "haunt",
		"haven", "hawk", "hazel", "heath", "hedge", "helix", "helm", "herb",
		"hickory", "hill", "hive", "hold", "hollow", "home", "honey", "hope",
		"horn", "horse", "hound", "house", "hull", "husk", "icy", "idle",
		"igloo", "ink", "inlet", "inn", "iris", "iron", "isle", "ivy",
		"jade", "jar", "jasper", "jay", "jazz", "jelly", "jet", "jewel",
		"joust", "joyful", "judge", "juniper", "kale", "kayak", "kelp", "kernel",
		"kettle", "key", "kilo", "kimono", "kite", "knife", "knoll", "koala",
		"label", "lake", "lamb", "lamp", "lance", "lane", "lantern", "larch",
		"lark", "laurel", "lava", "leaf", "ledge", "lemon", "lens", "lever",
		"light", "lily", "lime", "line", "linen", "lion", "locust", "lodge",
		"loft", "log", "lotus", "lunar", "lupine", "lynx", "magnet", "maple",
		"mare", "marsh", "mask", "mast", "match", "meadow", "melon", "mesa",
		"metal", "mica", "milk", "mill", "mink", "mint", "mist", "model",
		"moon", "moss", "motor", "mound", "moth", "motor", "mud", "mulch",
		"muse", "music", "nacre", "napa", "navy", "nebula", "needle", "nectar",
		"nest", "net", "night", "noble", "north", "nova", "nut", "oak",
		"oasis", "oat", "ocean", "ochre", "odd", "oil", "olive", "omega",
		"onion", "onyx", "opal", "orange", "orbit", "orca", "organ", "otter",
		"oval", "owl", "oxide", "pact", "pagoda", "palm", "panda", "pantry",
		"papaya", "paper", "parcel", "park", "parrot", "pasta", "path", "patio",
		"peach", "pearl", "pecan", "pedal", "pelican", "perch", "peril", "petal",
		"phase", "pier", "pilot", "pine", "piper", "pixel", "place", "plain",
		"plant", "plaza", "plow", "plumb", "plume", "plunge", "pod", "point",
		"polar", "pollen", "pond", "poppy", "portal", "potion", "prairie", "prime",
		"prism", "proud", "puma", "purple", "quartz", "quay", "quest", "quick",
		"quill", "quilt", "quince", "quiet", "radish", "raft", "rain", "rally",
		"ramp", "ranger", "rapid", "raven", "ravine", "ray", "reach", "reef",
		"relay", "rhino", "rhyme", "ribbon", "ridge", "riot", "ripple", "river",
		"road", "robin", "rock", "roof", "rose", "roster", "rover", "rowan",
		"ruby", "rudder", "runic", "rural", "rush", "saddle", "safari", "saffron",
		"sage", "salmon", "salt", "sand", "sandal", "sapphire", "satin", "scale",
		"scarf", "school", "scout", "script", "sea", "seal", "seed", "selva",
		"sepia", "serene", "shade", "shell", "shield", "shore", "silo", "silver",
		"skate", "skip", "sky", "slate", "sleek", "sled", "sloop", "smoke",
		"snap", "snow", "solar", "solid", "song", "soot", "sound", "south",
		"spark", "spider", "spin", "spool", "spring", "spruce", "square", "stable",
		"stag", "staple", "star", "statue", "steam", "stem", "stern", "stone",
		"stork", "storm", "stream", "strike", "sugar", "summit", "sun", "swamp",
		"swan", "switch", "sword", "tabby", "table", "tacit", "tadpole", "taiga",
		"talent", "talon", "tan", "tangle", "tapir", "tarn", "teal", "tempo",
		"tent", "tether", "thatch", "thaw", "thorn", "thyme", "tidal", "tide",
		"tiger", "tile", "tinder", "tint", "tonic", "topaz", "torch", "totem",
		"tower", "trace", "track", "trail", "train", "trance", "trap", "travel",
		"tread", "treble", "tree", "trek", "trellis", "trend", "tribe", "trove",
		"truck", "trust", "tulip", "tundra", "tuner", "turf", "turn", "tusk",
		"twig", "twine", "umber", "union", "unit", "urban", "urchin", "vale",
		"valor", "valve", "vane", "vapor", "vector", "velvet", "verge", "verse",
		"vine", "violet", "vision", "vixen", "vogue", "voice", "volt", "vortex",
		"wagon", "waldo", "walker", "wand", "warmth", "water", "wave", "weave",
		"wedge", "west", "whale", "wheat", "wheel", "whim", "whisk", "white",
		"wick", "wild", "willow", "wind", "wine", "wing", "winter", "wisp",
		"wolf", "wonder", "woolen", "wren", "xenon", "yacht", "yarn", "year",
		"yeast", "yellow", "yield", "yoga", "yolk", "yonder", "yucca", "zebra",
		"zenith", "zephyr", "zest", "zigzag", "zinc", "zone",
	}
	// Pad to 8192 by repeating with index suffix — not cryptographic
	// quality padding but keeps the format valid for tests + dev.
	// Production builds should embed a real 8192-entry wordlist.
	out := make([]string, 0, 8192)
	for len(out) < 8192 {
		for _, w := range base {
			if len(out) >= 8192 {
				break
			}
			if len(out) < len(base) {
				out = append(out, w)
			} else {
				out = append(out, fmt.Sprintf("%s%d", w, len(out)/len(base)))
			}
		}
	}
	return out
}()
