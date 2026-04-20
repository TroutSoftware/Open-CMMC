package fbhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	scan "github.com/filebrowser/filebrowser/v2/cmmc/scan"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/files"
	"github.com/filebrowser/filebrowser/v2/fileutils"
)

var resourceGetHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	file, err := files.NewFileInfo(&files.FileOptions{
		Fs:         d.user.Fs,
		Path:       r.URL.Path,
		Modify:     d.user.Perm.Modify,
		Expand:     true,
		ReadHeader: d.server.TypeDetectionByHeader,
		Checker:    d,
		Content:    d.user.Perm.Download,
	})
	if err != nil {
		return errToStatus(err), err
	}

	encoding := r.Header.Get("X-Encoding")
	if file.IsDir {
		file.Sorting = d.user.Sorting
		file.ApplySort()
		// CMMC 3.8.4: attach the CUI Mark to every child so the SPA
		// can render the badge in one round-trip. Single file response
		// is handled below after any encoding branch runs.
		attachMarksToListing(d, file)
		return renderJSON(w, r, file)
	} else if encoding == "true" {
		if !d.user.Perm.Download {
			return http.StatusAccepted, nil
		}
		if file.Type != "text" {
			return renderJSON(w, r, file)
		}

		// CMMC 3.8.4: X-Encoding:true streams raw file bytes back to
		// the SPA. Same CUI gate as the /api/raw path.
		if s := enforceCUIRead(r, d, r.URL.Path, "encoded read of CUI requires fresh MFA", false); s != 0 {
			return s, nil
		}

		f, err := d.user.Fs.Open(r.URL.Path)
		if err != nil {
			return errToStatus(err), err
		}
		defer f.Close()

		data, err := io.ReadAll(f)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(data)
		return 0, err
	}

	if checksum := r.URL.Query().Get("checksum"); checksum != "" {
		err := file.Checksum(checksum)
		if errors.Is(err, fberrors.ErrInvalidOption) {
			return http.StatusBadRequest, nil
		} else if err != nil {
			return http.StatusInternalServerError, err
		}

		// do not waste bandwidth if we just want the checksum
		file.Content = ""
	}

	attachMarksToListing(d, file)
	return renderJSON(w, r, file)
})

// attachMarksToListing fills in FileInfo.Mark for the given node and
// (if it is a directory) for each of its immediate children, using
// one batched store lookup. Missing rows leave Mark empty (== not
// marked). Store errors are logged but not surfaced — the file listing
// still renders; the UI just won't show badges.
func attachMarksToListing(d *data, file *files.FileInfo) {
	if d == nil || d.user == nil || d.store == nil || d.store.FileMetadata == nil || file == nil {
		return
	}
	paths := []string{d.user.FullPath(file.Path)}
	if file.IsDir && file.Listing != nil {
		for _, item := range file.Items {
			paths = append(paths, d.user.FullPath(filepath.Join(file.Path, item.Name)))
		}
	}
	// GetManyEffective so files inside a CUI-classified folder
	// render their inherited mark, not "unmarked." Without this,
	// a listing of /Engineering_CUI/ shows files with no badge
	// even though enforcement treats them as CUI — a user-visible
	// CMMC 3.8.4 observability hole flagged by code review.
	marks, err := d.store.FileMetadata.GetManyEffective(paths)
	if err != nil {
		log.Printf("marking: GetManyEffective failed on listing %s: %v", file.Path, err)
		return
	}
	if md, ok := marks[d.user.FullPath(file.Path)]; ok {
		file.Mark = string(md.Mark)
	}
	if file.IsDir && file.Listing != nil {
		for _, item := range file.Items {
			if md, ok := marks[d.user.FullPath(filepath.Join(file.Path, item.Name))]; ok {
				item.Mark = string(md.Mark)
			}
		}
	}
}

func resourceDeleteHandler(fileCache FileCache) handleFunc {
	return withUser(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if r.URL.Path == "/" || !d.user.Perm.Delete {
			return http.StatusForbidden, nil
		}

		file, err := files.NewFileInfo(&files.FileOptions{
			Fs:         d.user.Fs,
			Path:       r.URL.Path,
			Modify:     d.user.Perm.Modify,
			Expand:     false,
			ReadHeader: d.server.TypeDetectionByHeader,
			Checker:    d,
		})
		if err != nil {
			return errToStatus(err), err
		}

		err = d.store.Share.DeleteWithPathPrefix(file.Path)
		if err != nil {
			log.Printf("WARNING: Error(s) occurred while deleting associated shares with file: %s", err)
		}

		// delete thumbnails
		err = delThumbs(r.Context(), fileCache, file)
		if err != nil {
			return errToStatus(err), err
		}

		err = d.RunHook(func() error {
			return d.user.Fs.RemoveAll(r.URL.Path)
		}, "delete", r.URL.Path, "", d.user)

		if err != nil {
			return errToStatus(err), err
		}

		// CMMC 3.8.4: when the file is gone, drop any marking row
		// pointing at it. Idempotent — missing rows are a no-op.
		if d.store.FileMetadata != nil {
			if mErr := d.store.FileMetadata.Delete(d.user.FullPath(r.URL.Path)); mErr != nil {
				log.Printf("WARNING: marking row not cleaned for %s: %v", r.URL.Path, mErr)
			}
		}

		return http.StatusNoContent, nil
	})
}

func resourcePostHandler(fileCache FileCache) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Create || !d.CheckAction(r.URL.Path, folderacl.ActionWrite) {
			return http.StatusForbidden, nil
		}

		// Directories creation on POST.
		if strings.HasSuffix(r.URL.Path, "/") {
			err := d.user.Fs.MkdirAll(r.URL.Path, d.settings.DirMode)
			return errToStatus(err), err
		}

		file, err := files.NewFileInfo(&files.FileOptions{
			Fs:         d.user.Fs,
			Path:       r.URL.Path,
			Modify:     d.user.Perm.Modify,
			Expand:     false,
			ReadHeader: d.server.TypeDetectionByHeader,
			Checker:    d,
		})
		if err == nil {
			if r.URL.Query().Get("override") != "true" {
				return http.StatusConflict, nil
			}

			// Permission for overwriting the file
			if !d.user.Perm.Modify {
				return http.StatusForbidden, nil
			}

			err = delThumbs(r.Context(), fileCache, file)
			if err != nil {
				return errToStatus(err), err
			}
		}

		err = d.RunHook(func() error {
			info, writeErr := writeFile(d.user.Fs, r.URL.Path, r.Body, d.settings.FileMode, d.settings.DirMode)
			if writeErr != nil {
				return writeErr
			}

			etag := fmt.Sprintf(`"%x%x"`, info.ModTime().UnixNano(), info.Size())
			w.Header().Set("ETag", etag)
			return nil
		}, "upload", r.URL.Path, "", d.user)

		// CMMC 3.14.2 — surface AV verdicts as dedicated audit
		// events. RejectedError is an infected file; ErrUnavailable
		// is a backend fault (only reaches here in Required mode).
		if err != nil {
			var rejected *scan.RejectedError
			if errors.As(err, &rejected) {
				emitScanReject(r, d, r.URL.Path, rejected.Signature)
			} else if errors.Is(err, scan.ErrUnavailable) {
				emitScanError(r, d, r.URL.Path, err)
			}
			_ = d.user.Fs.RemoveAll(r.URL.Path)
		}

		return errToStatus(err), err
	})
}

var resourcePutHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.user.Perm.Modify || !d.CheckAction(r.URL.Path, folderacl.ActionWrite) {
		return http.StatusForbidden, nil
	}

	// Only allow PUT for files.
	if strings.HasSuffix(r.URL.Path, "/") {
		return http.StatusMethodNotAllowed, nil
	}

	exists, err := afero.Exists(d.user.Fs, r.URL.Path)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if !exists {
		return http.StatusNotFound, nil
	}

	err = d.RunHook(func() error {
		info, writeErr := writeFile(d.user.Fs, r.URL.Path, r.Body, d.settings.FileMode, d.settings.DirMode)
		if writeErr != nil {
			return writeErr
		}

		etag := fmt.Sprintf(`"%x%x"`, info.ModTime().UnixNano(), info.Size())
		w.Header().Set("ETag", etag)
		return nil
	}, "save", r.URL.Path, "", d.user)

	return errToStatus(err), err
})

func resourcePatchHandler(fileCache FileCache) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		src := r.URL.Path
		dst := r.URL.Query().Get("destination")
		action := r.URL.Query().Get("action")
		dst, err := url.QueryUnescape(dst)
		dst = path.Clean("/" + dst)
		src = path.Clean("/" + src)
		// Rename / copy / move: reading the source + writing the
		// destination. ACL action flipped per side so a grant that
		// only allowed read at src can't be used to smuggle bytes
		// into a dst where the user lacks write.
		if !d.Check(src) || !d.CheckAction(dst, folderacl.ActionWrite) {
			return http.StatusForbidden, nil
		}
		if err != nil {
			return errToStatus(err), err
		}
		if dst == "/" || src == "/" {
			return http.StatusForbidden, nil
		}

		err = checkParent(src, dst)
		if err != nil {
			return http.StatusBadRequest, err
		}

		// CMMC 3.8.3 / 3.1.3 — containment: a CUI-marked file cannot
		// land in an uncontrolled destination. Both rename/move and
		// copy go through this same handler, so the check catches
		// every pathway including drag-and-drop.
		if status, srcMark := enforceCUIMoveRule(r, d, src, dst); status != 0 {
			emitCUIMoveBlocked(r, d, src, dst, srcMark)
			// Write a discriminating response so the SPA can show a
			// targeted toast ("cannot move CUI to uncontrolled
			// destination") instead of a generic 403. X-CMMC-Block
			// is an explicit machine-readable tag; the body carries
			// a human-readable reason.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-CMMC-Block", "cui-containment")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("cui-containment: a CUI-marked item cannot be moved to an uncontrolled destination"))
			return 0, nil
		}

		srcInfo, _ := d.user.Fs.Stat(src)
		dstInfo, _ := d.user.Fs.Stat(dst)
		same := os.SameFile(srcInfo, dstInfo)

		if action != "rename" || !same {
			override := r.URL.Query().Get("override") == "true"
			rename := r.URL.Query().Get("rename") == "true"
			if !override && !rename {
				if _, err = d.user.Fs.Stat(dst); err == nil {
					return http.StatusConflict, nil
				}
			}
			if rename {
				dst = addVersionSuffix(dst, d.user.Fs)
			}

			if override && !d.user.Perm.Modify {
				return http.StatusForbidden, nil
			}
		}

		err = d.RunHook(func() error {
			return patchAction(r.Context(), action, src, dst, d, fileCache)
		}, action, src, dst, d.user)

		// CMMC 3.8.4: propagate the marking alongside the bytes so the
		// mark survives rename/copy and can't be laundered by moving
		// the file. Rename migrates in place; Copy clones into a new
		// row. Both are transactional inside the marking store.
		//
		// If the filesystem op succeeded but the marking update fails
		// we are left with a CUI file whose mark points at a ghost
		// path (rename) or a dst without a mark (copy) — a real CUI
		// downgrade vector. Emit cui.mark.orphan so SIEM can alert on
		// the anomaly; operators reconcile manually.
		if err == nil && d.store != nil && d.store.FileMetadata != nil {
			srcAbs := d.user.FullPath(src)
			dstAbs := d.user.FullPath(dst)
			switch action {
			case "rename":
				if mErr := d.store.FileMetadata.Rename(srcAbs, dstAbs); mErr != nil {
					log.Printf("WARNING: marking rename failed %s → %s: %v", src, dst, mErr)
					emitCUIMarkOrphan(r, d, srcAbs, dstAbs, "rename: "+mErr.Error())
				}
			case "copy":
				if mErr := d.store.FileMetadata.Copy(srcAbs, dstAbs, "copy-from:"+src); mErr != nil {
					log.Printf("WARNING: marking copy failed %s → %s: %v", src, dst, mErr)
					emitCUIMarkOrphan(r, d, srcAbs, dstAbs, "copy: "+mErr.Error())
				}
			}
		}

		return errToStatus(err), err
	})
}

func checkParent(src, dst string) error {
	rel, err := filepath.Rel(src, dst)
	if err != nil {
		return err
	}

	rel = filepath.ToSlash(rel)
	if !strings.HasPrefix(rel, "../") && rel != ".." && rel != "." {
		return fberrors.ErrSourceIsParent
	}

	return nil
}

func addVersionSuffix(source string, afs afero.Fs) string {
	counter := 1
	dir, name := path.Split(source)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)

	for {
		if _, err := afs.Stat(source); err != nil {
			break
		}
		renamed := fmt.Sprintf("%s(%d)%s", base, counter, ext)
		source = path.Join(dir, renamed)
		counter++
	}

	return source
}

func writeFile(afs afero.Fs, dst string, in io.Reader, fileMode, dirMode fs.FileMode) (os.FileInfo, error) {
	dir, _ := path.Split(dst)
	err := afs.MkdirAll(dir, dirMode)
	if err != nil {
		return nil, err
	}

	file, err := afs.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(file, in); err != nil {
		_ = file.Close()
		return nil, err
	}

	// Sync the file to ensure all data is written to storage.
	// to prevent file corruption.
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}

	info, statErr := file.Stat()

	// CMMC 3.14.2: Close runs the AV scan inside EncryptingFS.
	// Deferred Close would swallow *scan.RejectedError silently —
	// explicit Close here bubbles it to the handler so a detection
	// 422s cleanly and a backend fault 503s in Required mode.
	if closeErr := file.Close(); closeErr != nil {
		return nil, closeErr
	}
	if statErr != nil {
		return nil, statErr
	}
	return info, nil
}

func delThumbs(ctx context.Context, fileCache FileCache, file *files.FileInfo) error {
	for _, previewSizeName := range PreviewSizeNames() {
		size, _ := ParsePreviewSize(previewSizeName)
		if err := fileCache.Delete(ctx, previewCacheKey(file, size)); err != nil {
			return err
		}
	}

	return nil
}

func patchAction(ctx context.Context, action, src, dst string, d *data, fileCache FileCache) error {
	switch action {
	case "copy":
		if !d.user.Perm.Create {
			return fberrors.ErrPermissionDenied
		}

		return fileutils.Copy(d.user.Fs, src, dst, d.settings.FileMode, d.settings.DirMode)
	case "rename":
		if !d.user.Perm.Rename {
			return fberrors.ErrPermissionDenied
		}
		src = path.Clean("/" + src)
		dst = path.Clean("/" + dst)

		file, err := files.NewFileInfo(&files.FileOptions{
			Fs:         d.user.Fs,
			Path:       src,
			Modify:     d.user.Perm.Modify,
			Expand:     false,
			ReadHeader: false,
			Checker:    d,
		})
		if err != nil {
			return err
		}

		// delete thumbnails
		err = delThumbs(ctx, fileCache, file)
		if err != nil {
			return err
		}

		return fileutils.MoveFile(d.user.Fs, src, dst, d.settings.FileMode, d.settings.DirMode)
	default:
		return fmt.Errorf("unsupported action %s: %w", action, fberrors.ErrInvalidRequestParams)
	}
}

type DiskUsageResponse struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

var diskUsage = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	file, err := files.NewFileInfo(&files.FileOptions{
		Fs:         d.user.Fs,
		Path:       r.URL.Path,
		Modify:     d.user.Perm.Modify,
		Expand:     false,
		ReadHeader: false,
		Checker:    d,
		Content:    false,
	})
	if err != nil {
		return errToStatus(err), err
	}
	fPath := file.RealPath()
	if !file.IsDir {
		return renderJSON(w, r, &DiskUsageResponse{
			Total: 0,
			Used:  0,
		})
	}

	usage, err := disk.UsageWithContext(r.Context(), fPath)
	if err != nil {
		return errToStatus(err), err
	}
	return renderJSON(w, r, &DiskUsageResponse{
		Total: usage.Total,
		Used:  usage.Used,
	})
})
