package fbhttp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/share"
)

func withPermShare(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Share || !d.user.Perm.Download {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

var shareListHandler = withPermShare(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	var (
		s   []*share.Link
		err error
	)
	if d.user.Perm.Admin {
		s, err = d.store.Share.All()
	} else {
		s, err = d.store.Share.FindByUserID(d.user.ID)
	}
	if errors.Is(err, fberrors.ErrNotExist) {
		return renderJSON(w, r, []*share.Link{})
	}

	if err != nil {
		return http.StatusInternalServerError, err
	}

	sort.Slice(s, func(i, j int) bool {
		if s[i].UserID != s[j].UserID {
			return s[i].UserID < s[j].UserID
		}
		return s[i].Expire < s[j].Expire
	})

	return renderJSON(w, r, s)
})

var shareGetsHandler = withPermShare(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	s, err := d.store.Share.Gets(r.URL.Path, d.user.ID)
	if errors.Is(err, fberrors.ErrNotExist) {
		return renderJSON(w, r, []*share.Link{})
	}

	if err != nil {
		return http.StatusInternalServerError, err
	}

	return renderJSON(w, r, s)
})

var shareDeleteHandler = withPermShare(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	hash := strings.TrimSuffix(r.URL.Path, "/")
	hash = strings.TrimPrefix(hash, "/")

	if hash == "" {
		return http.StatusBadRequest, nil
	}

	link, err := d.store.Share.GetByHash(hash)
	if err != nil {
		return errToStatus(err), err
	}

	if link.UserID != d.user.ID && !d.user.Perm.Admin {
		return http.StatusForbidden, nil
	}

	err = d.store.Share.Delete(hash)
	return errToStatus(err), err
})

var sharePostHandler = withPermShare(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	// External sharing of CUI is out of scope for this release:
	// CUI stays inside the filebrowser and is accessible only to
	// authenticated users with folder permissions. Public-share
	// creation for a CUI-marked path is therefore refused; the
	// user is pointed at the "direct link" in the Share modal,
	// which bounces recipients through Keycloak. The rejection
	// is audit-stamped so SIEM still sees the attempt (3.1.22
	// / 3.8.4).
	mark, err := cuiMarkFor(d, r.URL.Path)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if !mark.AllowsPublicShare() {
		emitCUIAccessReject(r, d, mark, http.StatusForbidden, "public share of CUI refused: external sharing out of scope")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-CMMC-Block", "cui-no-public-share")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cui-no-public-share: use the direct link in the Share modal — CUI stays on the filebrowser"))
		return 0, nil
	}

	var s *share.Link
	var body share.CreateBody
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to decode body: %w", err)
		}
		defer r.Body.Close()
	}

	bytes := make([]byte, 6)
	if _, err = rand.Read(bytes); err != nil {
		return http.StatusInternalServerError, err
	}

	str := base64.URLEncoding.EncodeToString(bytes)

	var expire int64 = 0

	if body.Expires != "" {
		num, err := strconv.Atoi(body.Expires)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		var add time.Duration
		switch body.Unit {
		case "seconds":
			add = time.Second * time.Duration(num)
		case "minutes":
			add = time.Minute * time.Duration(num)
		case "days":
			add = time.Hour * 24 * time.Duration(num)
		default:
			add = time.Hour * time.Duration(num)
		}

		expire = time.Now().Add(add).Unix()
	}

	hash, status, err := getSharePasswordHash(body)
	if err != nil {
		return status, err
	}

	var token string
	if len(hash) > 0 {
		tokenBuffer := make([]byte, 96)
		if _, err := rand.Read(tokenBuffer); err != nil {
			return http.StatusInternalServerError, err
		}
		token = base64.URLEncoding.EncodeToString(tokenBuffer)
	}

	s = &share.Link{
		Path:         r.URL.Path,
		Hash:         str,
		Expire:       expire,
		UserID:       d.user.ID,
		PasswordHash: string(hash),
		Token:        token,
	}

	if err := d.store.Share.Save(s); err != nil {
		return http.StatusInternalServerError, err
	}

	return renderJSON(w, r, s)
})

func getSharePasswordHash(body share.CreateBody) (data []byte, statuscode int, err error) {
	if body.Password == "" {
		return nil, 0, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to hash password: %w", err)
	}

	return hash, 0, nil
}
