package fileops

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Resolve turns a (root, path) pair into an absolute path that is inside the
// root, contains no symlink on the way, and is not one of the excluded agent
// files. It is the single entry point every operation uses (design section
// 3.9).
func (o *Ops) Resolve(root, rel string) (string, error) {
	base, segs, err := o.resolveBase(root, rel)
	if err != nil {
		return "", err
	}
	if len(segs) == 0 {
		// "." names the root itself (file_list of the root directory).
		if err := o.checkExcluded(base); err != nil {
			return "", err
		}
		return base, nil
	}
	// Walk the directory part of the path one segment at a time. Each step is
	// checked with Lstat and opened with O_NOFOLLOW, so a symlink is refused
	// rather than followed (design section 3.9).
	dir := base
	for _, seg := range segs[:len(segs)-1] {
		dir = filepath.Join(dir, seg)
		if err := o.checkSegment(dir, true); err != nil {
			return "", err
		}
	}
	full := filepath.Join(dir, segs[len(segs)-1])
	if err := o.checkSegment(full, false); err != nil {
		return "", err
	}
	if !o.opts.IsUnrestricted() && !within(base, full) {
		return "", fmt.Errorf("%w: %s is not inside %s", ErrOutsideRoots, full, base)
	}
	if err := o.checkExcluded(full); err != nil {
		return "", err
	}
	return full, nil
}

// resolveBase is the filesystem-free half of Resolve: it applies the syntax
// rules, the root lookup and the unrestricted rule, and returns the base
// directory (the root, or the volume root when unrestricted) with the cleaned
// relative segments. A caller that must create the path (Mkdir) uses it
// directly; Resolve adds the existence and symlink walk on top.
func (o *Ops) resolveBase(root, rel string) (string, []string, error) {
	if rel == "" {
		return "", nil, fmt.Errorf("%w: empty path", ErrBadPath)
	}
	if strings.ContainsRune(rel, 0) {
		return "", nil, fmt.Errorf("%w: NUL in path", ErrBadPath)
	}
	rel = normalizeSeparators(rel)
	if strings.ContainsRune(rel, '\\') {
		// On Unix a backslash is a legal file name character, not a
		// separator. Refusing it keeps one rule for both platforms: a path
		// written with Windows separators is rejected instead of silently
		// naming a different file.
		return "", nil, fmt.Errorf("%w: backslash in path %q", ErrBadPath, rel)
	}

	var base string
	if r, named := o.roots[root]; named && root != "" {
		// A named root ("xray", "state") keeps meaning a root plus a relative
		// path in unrestricted mode too: the panel's managed-file views use
		// it. Unrestricted only adds the empty root with an absolute path.
		base = r.Path
	} else if o.opts.IsUnrestricted() {
		abs := filepath.Clean(rel)
		if !filepath.IsAbs(abs) {
			return "", nil, fmt.Errorf("%w: Files.Unrestricted needs an absolute path, got %q", ErrBadPath, rel)
		}
		// The volume root is the base and the rest is the relative path, so
		// the segment walk below works the same way on Windows.
		base = filepath.VolumeName(abs) + string(filepath.Separator)
		rel = strings.TrimPrefix(strings.TrimPrefix(abs, filepath.VolumeName(abs)), string(filepath.Separator))
	} else {
		r, ok := o.roots[root]
		if !ok {
			if len(o.roots) == 0 {
				return "", nil, fmt.Errorf("%w: file operations have no roots", ErrNoRoots)
			}
			return "", nil, fmt.Errorf("%w: %q (configured: %s)", ErrUnknownRoot, root, strings.Join(o.RootNames(), ", "))
		}
		base = r.Path
	}
	if filepath.IsAbs(rel) {
		return "", nil, fmt.Errorf("%w: absolute path %q", ErrBadPath, rel)
	}

	segs, err := splitSegments(rel)
	if err != nil {
		return "", nil, err
	}
	return base, segs, nil
}

// checkSegment verifies one path component: no symlink, and a directory when
// wantDir is set. A missing final component is fine (file_write creates it).
func (o *Ops) checkSegment(p string, wantDir bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if wantDir {
				return fmt.Errorf("%w: %s does not exist", ErrBadPath, p)
			}
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, p)
	}
	if wantDir && !fi.IsDir() {
		return fmt.Errorf("%w: %s", ErrNotDir, p)
	}
	// Re-open with O_NOFOLLOW as the anti-TOCTOU half of the check: a path
	// swapped for a symlink between the Lstat and this call fails here.
	f, err := openNoFollow(p, wantDir)
	if err != nil {
		if isSymlinkErr(err) {
			return fmt.Errorf("%w: %s", ErrSymlink, p)
		}
		return err
	}
	defer f.Close()
	return nil
}

// checkExcluded refuses the agent's own files even when a root contains them.
func (o *Ops) checkExcluded(p string) error {
	for _, e := range o.excl {
		if samePath(p, e) {
			return fmt.Errorf("%w: %s is never managed", ErrOutsideRoots, p)
		}
	}
	return nil
}

// splitSegments cleans a relative path and returns its components. It refuses
// "..", absolute paths and empty components. The root itself ("." or "") yields
// no components, which Resolve turns into the root directory.
func splitSegments(rel string) ([]string, error) {
	clean := path.Clean(strings.ReplaceAll(rel, string(filepath.Separator), "/"))
	if clean == "." || clean == "" {
		return nil, nil
	}
	if clean == "/" {
		return nil, fmt.Errorf("%w: absolute path %q", ErrBadPath, rel)
	}
	if strings.HasPrefix(clean, "/") {
		return nil, fmt.Errorf("%w: absolute path %q", ErrBadPath, rel)
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		if s == ".." {
			return nil, fmt.Errorf("%w: %q escapes the root", ErrBadPath, rel)
		}
		if s == "" || s == "." {
			return nil, fmt.Errorf("%w: %q has an empty segment", ErrBadPath, rel)
		}
	}
	return segs, nil
}

// normalizeSeparators turns a Windows-style path into the platform's form.
// On Unix it is the identity: a backslash there is an ordinary character, and
// Resolve refuses it rather than guessing.
func normalizeSeparators(p string) string {
	if runtimeIsWindows {
		return strings.ReplaceAll(p, "\\", "/")
	}
	return p
}

// within reports whether p is base or sits below it.
func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// samePath compares two absolute paths, case-insensitively on Windows.
func samePath(a, b string) bool {
	if runtimeIsWindows {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// checkRoot validates a configured root.
func checkRoot(p string, allowSystem bool) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("root %q must be absolute", p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if fi, err := os.Stat(abs); err == nil {
		if !fi.IsDir() {
			return "", fmt.Errorf("root %s is not a directory", abs)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if !allowSystem {
		if err := checkRootIsSane(abs); err != nil {
			return "", err
		}
	}
	return abs, nil
}

// systemRoots are the directories a root must never be inside: handing the
// panel one of them would make the roots check meaningless (design section
// 3.9 rule 1). /tmp, /home and /root are deliberately absent: a root below
// them is still confined, and the agent's own files are excluded separately.
var systemRoots = []string{"/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys"}

// pseudoRoots are kernel/device trees: nothing below them is ever a sane root.
// The other system directories are refused only as themselves (`/etc`), not
// their application subdirectories: the agent's own default root is its config
// directory, which is /etc/W1nCray on every standard install.
var pseudoRoots = []string{"/dev", "/proc", "/sys"}

// checkRootIsSane refuses a filesystem root, a system directory itself, anything
// below a pseudo filesystem, and demands at least two path levels below the
// filesystem root.
func checkRootIsSane(abs string) error {
	vol := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs, vol)
	if rest == "/" || rest == "" {
		return fmt.Errorf("root %s is a filesystem root", abs)
	}
	cleaned := filepath.ToSlash(rest)
	for _, sys := range systemRoots {
		if cleaned == sys {
			return fmt.Errorf("root %s is a system directory", abs)
		}
	}
	for _, sys := range pseudoRoots {
		if strings.HasPrefix(cleaned, sys+"/") {
			return fmt.Errorf("root %s is inside a system directory (%s)", abs, sys)
		}
	}
	if depth(cleaned) < 2 {
		return fmt.Errorf("root %s is too shallow: at least two levels below the filesystem root are required", abs)
	}
	return nil
}

func depth(p string) int {
	n := 0
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s != "" {
			n++
		}
	}
	return n
}

// entryType maps a file mode onto the contract's file_list type.
func entryType(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "link"
	case m.IsDir():
		return "dir"
	case m.IsRegular():
		return "file"
	default:
		return "other"
	}
}

// syncDir flushes directory metadata so the rename survives a crash. Best
// effort: some platforms cannot fsync a directory.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
