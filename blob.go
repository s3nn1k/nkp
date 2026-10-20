// blob.go — blob-режим: файл шифруется целиком как одно AEAD-тело.
//
// Формат .nkpb v1: "NKPB1\n" + JSON-заголовок + "\n" + шифротекст;
// AAD = magic+заголовок (тамперинг любого поля ломает тег).
// Плоский (unlocked) файл: служебная шапка `# nkp:v1 …` + тело байт-в-байт.
// seal/unlock/lock НЕ парсят содержимое тела; парсинг секций — только list/show.
// Сверки при lock: (1) оригинальный мастер — открываем текущий блоб;
// (2) блоб не уезжал с момента unlock — anchor из шапки (self-advance после краша
//
//	seal-до-wipe распознаётся и лечится простым wipe); правок нет — перезапечатки нет.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// warnStaleAfter — сколько нетронутый разлоченный flat ещё считается нормальным
// в info; дольше — помечаем "⚠ too long".
const warnStaleAfter = 5 * time.Minute

const (
	blobMagicStr  = "NKPB1\n"
	blobExt       = ".nkpb"
	flatExt       = ".txt" // пара: <stem>.txt (flat) ↔ <stem>.nkpb (блоб)
	flatHdrPrefix = "# nkp:v1 "
)

// resolvePair превращает аргумент команды в пару путей flat/blob.
// Принимаются: <stem> | <stem>.txt | <stem>.nkpb | каталог (внутри ровно один .nkpb).
func resolvePair(arg string) (flat, blob string) {
	a, err := filepath.Abs(arg)
	if err != nil {
		die("%v", err)
	}
	if st, err := os.Stat(a); err == nil && st.IsDir() {
		var found []string
		ents, _ := os.ReadDir(a)
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), blobExt) && !e.IsDir() {
				found = append(found, filepath.Join(a, e.Name()))
			}
		}
		if len(found) != 1 {
			die("%s: expected exactly one *%s inside, found %d", a, blobExt, len(found))
		}
		blob = found[0]
		return pairFromBlob(blob)
	}
	switch {
	case strings.HasSuffix(a, blobExt):
		return pairFromBlob(a)
	case strings.HasSuffix(a, flatExt):
		blob = strings.TrimSuffix(a, flatExt) + blobExt
	default:
		blob = a + blobExt
	}
	return strings.TrimSuffix(blob, blobExt) + flatExt, blob
}

func pairFromBlob(blob string) (flat, b string) {
	stem := strings.TrimSuffix(blob, blobExt)
	if err := validBaseName(filepath.Base(stem)); err != nil {
		die("%v", err)
	}
	return stem + flatExt, blob
}

// dbPrompt собирает подсказку вида "[main] master: " — при lock --all и в общем
// потоке ввод должен быть привязан к базе.
func dbPrompt(blob, what string) string {
	name := strings.TrimSuffix(filepath.Base(blob), blobExt)
	return fmt.Sprintf("[%s] %s", name, what)
}

// promptMaster читает мастер-пароль и отвергает пустой (пустой мастер = vault,
// дешифруемый одним Enter'ом).
func promptMaster(prompt string) ([]byte, error) {
	pw, err := readPwd(prompt)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("master must not be empty")
	}
	return pw, nil
}

// requireRegular запрещает симлинки и спец-файлы: чтение запечатало бы чужой
// контент, wipe — уничтожил бы цель ссылки.
func requireRegular(path, what string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s %s is a symlink or not a regular file — refusing", what, path)
	}
	return nil
}

// sweepTemps вычищает остатки .nkp-tmp-* (краш между записью и rename мог
// оставить plaintext). Только файлы старше минуты — не трогаем параллельные
// процессы.
func sweepTemps(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-time.Minute)
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, ".nkp-tmp-") {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, name))
		}
	}
}

// validBaseName: имя базы без пробелов/'=' — иначе поле blob= шапки flat-файла
// становится непарсибельным и сверки молча выключаются.
func validBaseName(base string) error {
	if strings.ContainsAny(base, " \t=") {
		return fmt.Errorf("base name %q must not contain spaces or '=' (breaks the flat header)", base)
	}
	return nil
}

// validateKDF ограждает от крафтовых заголовков (panic в Argon2id, гигантские
// аллокации) и от опечаток в флагах init/rekey.
func validateKDF(k kdfParams) error {
	if k.Algorithm != "argon2id" {
		return fmt.Errorf("unsupported KDF algorithm %q", k.Algorithm)
	}
	if k.Time < 1 || k.Time > 64 {
		return fmt.Errorf("argon2id time=%d out of range 1..64", k.Time)
	}
	if k.MemoryMiB < 1 || k.MemoryMiB > 16384 {
		return fmt.Errorf("argon2id memory=%dMiB out of range 1..16384", k.MemoryMiB)
	}
	if k.Parallelism < 1 || k.Parallelism > 64 {
		return fmt.Errorf("argon2id parallelism=%d out of range 1..64", k.Parallelism)
	}
	return nil
}

// fileFlag — общий флаг --file: сырой <stem>.txt/.nkpb путь вместо имени базы.
func fileFlag(fs *flag.FlagSet) *string {
	return fs.String("file", "", "raw <stem>.txt/.nkpb path instead of a db name")
}

// resolveBase: голое имя базы -> пара в $NKP_VAULT (каталог, без подпапок).
func resolveBase(name string) (flat, blob string) {
	if strings.Contains(name, "/") || strings.HasSuffix(name, blobExt) ||
		strings.HasSuffix(name, flatExt) || strings.HasSuffix(name, ".nkp") {
		die("%q looks like a file — raw paths go through --file; positional args are db names", name)
	}
	dir := os.Getenv("NKP_VAULT")
	if dir == "" {
		die("NKP_VAULT is not set - export the vault directory holding <name>.nkpb bases")
	}
	if err := validBaseName(name); err != nil {
		die("%v", err)
	}
	return filepath.Join(dir, name+flatExt), filepath.Join(dir, name+blobExt)
}

// cmdPairArg: аргумент команды после fs.Parse — либо --file, либо имя базы.
func cmdPairArg(fs *flag.FlagSet, file *string) (flat, blob string) {
	if *file != "" {
		flat, blob = resolvePair(*file)
		sweepTemps(filepath.Dir(blob))
		return flat, blob
	}
	if fs.NArg() != 1 {
		die("missing <name> (or --file <path>)")
	}
	flat, blob = resolveBase(fs.Arg(0))
	sweepTemps(filepath.Dir(blob))
	return flat, blob
}

// viewPair: что показывать — flat без мастера, иначе блоб с мастером.
func viewPair(flat, blob string) (path string, isFlat bool) {
	if _, err := os.Stat(flat); err == nil {
		return flat, true
	}
	return blob, false
}

type blobHeader struct {
	KDF      kdfParams `json:"kdf"`
	Cipher   string    `json:"cipher"`
	Nonce    string    `json:"nonce"`
	LockedAt string    `json:"locked_at"`
}

type blobFile struct {
	aad []byte // magic + JSON-заголовок + "\n": AAD и якорь сверки (anchor)
	h   blobHeader
	ct  []byte
}

// --- служебные хелперы ---

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func fmtWarn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// atomicWrite пишет файл целиком через temp+fsync+rename; режим 0600
// (os.CreateTemp), как у saveVault — crash не оставляет половины файла.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".nkp-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op после успешного Rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func nowRFC() string { return time.Now().UTC().Format(time.RFC3339) }

// wipeFile затирает файл случайными байтами и удаляет (best-effort: APFS/SSD
// не гарантируют физического стирания свободных блоков).
func wipeFile(path string) {
	st, err := os.Lstat(path)
	if err != nil {
		return
	}
	// Симлинк: цель не трогаем — снимаем только ссылку.
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		os.Remove(path)
		return
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		const chunk = 64 << 10
		buf := make([]byte, chunk)
		for left := st.Size(); left > 0; {
			n := int64(chunk)
			if left < n {
				n = left
			}
			if _, err := rand.Read(buf[:n]); err != nil {
				break
			}
			if _, err := f.Write(buf[:n]); err != nil {
				break
			}
			left -= n
		}
		f.Sync()
		f.Close()
	}
	os.Remove(path)
}

// --- чтение/запись блоба ---

func loadBlobFile(path string) (*blobFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, []byte(blobMagicStr)) {
		return nil, fmt.Errorf("%s: not an nkp blob (no %q magic)", path, blobMagicStr)
	}
	rest := data[len(blobMagicStr):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("%s: truncated blob header", path)
	}
	var h blobHeader
	if err := json.Unmarshal(rest[:nl], &h); err != nil {
		return nil, fmt.Errorf("%s: bad blob header: %v", path, err)
	}
	if err := validateKDF(h.KDF); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if h.Cipher != cipherName {
		return nil, fmt.Errorf("%s: unsupported cipher %q", path, h.Cipher)
	}
	nonce, err := unb64(h.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("%s: bad nonce", path)
	}
	return &blobFile{aad: data[:len(blobMagicStr)+nl+1], h: h, ct: rest[nl+1:]}, nil
}

func blobKeyFrom(pw []byte, k kdfParams) []byte {
	salt, err := unb64(k.Salt)
	if err != nil {
		die("bad salt in blob header: %v", err)
	}
	return deriveKey(pw, salt, k)
}

func openBlob(b *blobFile, key []byte) ([]byte, error) {
	nonce, err := unb64(b.h.Nonce)
	if err != nil {
		return nil, err
	}
	return open(key, nonce, b.ct, b.aad)
}

// sealBlobFile запечатывает body с свежими salt+nonce (t/m/p — из base).
// Ключ выводится из pw заново под новый salt.
func sealBlobFile(path string, pw, body []byte, base kdfParams) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	k := base
	k.Salt = b64(salt)
	key := deriveKey(pw, salt, k)
	defer zero(key)

	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	h := blobHeader{KDF: k, Cipher: cipherName, Nonce: b64(nonce), LockedAt: nowRFC()}
	hdr, err := json.Marshal(h)
	if err != nil {
		return err
	}
	aad := append(append([]byte(blobMagicStr), hdr...), '\n')
	ct := a.Seal(nil, nonce, body, aad)
	return atomicWrite(path, append(aad, ct...))
}

// --- шапка плоского файла ---

type flatMeta struct {
	Blob   string
	Anchor string
	Body   string
}

// anchorOf — отпечаток заголовка блоба (12 hex); живёт в шапке flat-файла
// и при lock сверяется с текущим блобом (детект "блоб уехал").
func anchorOf(b *blobFile) string {
	sum := sha256.Sum256(b.aad)
	return hex.EncodeToString(sum[:6])
}

func bodyTag(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:6])
}

func flatHeaderLine(m flatMeta) string {
	return fmt.Sprintf("%sblob=%s anchor=%s body=%s",
		flatHdrPrefix, m.Blob, m.Anchor, m.Body)
}

// splitFlat делит файл на шапку и тело. Шапка опознаётся как наша только при
// полном парсе и совпадении blob= с expectedBlob (непустым) — иначе это контент.
func splitFlat(data []byte, expectedBlob string) (*flatMeta, []byte) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 || !bytes.HasPrefix(data, []byte(flatHdrPrefix)) {
		return nil, data
	}
	m, ok := parseFlatHeader(string(data[:nl]))
	if !ok || (expectedBlob != "" && m.Blob != expectedBlob) {
		return nil, data
	}
	return m, data[nl+1:]
}

func parseFlatHeader(line string) (*flatMeta, bool) {
	m := &flatMeta{}
	for _, f := range strings.Fields(strings.TrimPrefix(line, flatHdrPrefix)) {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			return nil, false
		}
		switch kv[0] {
		case "blob":
			m.Blob = kv[1]
		// неизвестные поля (напр. gen из старой шапки) игнорируются
		case "anchor":
			m.Anchor = kv[1]
		case "body":
			m.Body = kv[1]
		}
	}
	if m.Blob == "" || m.Anchor == "" || m.Body == "" {
		return nil, false
	}
	return m, true
}

// --- команды ---

// initTemplate — содержимое свежего flat-файла (шпаргалка + пример секции).
const initTemplate = `# Sections start with '#----[ name ]' at column 0; everything
# else is content (multi-line secrets, any '#' lines). Remove this cheat
# sheet and add your sections.

#----[ example ]
secret line 1
secret line 2
`

// cmdInit: nkp init [-t N -m MiB -p N] [-s] <stem | stem.txt | stem.nkpb>
// Создаёт blob-vault: <stem>.nkpb (мастер задаётся здесь, KDF из флагов)
// и разлоченный <stem>.txt со шпаргалкой. Если <stem>.txt уже существует —
// адаптирует его содержимое как есть (миграция существующего файла).
// Дальше только цикл unlock → edit → lock.
func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	t := fs.Uint("time", uint(defTime), "Argon2id iterations")
	fs.UintVar(t, "t", uint(defTime), "Argon2id iterations (shorthand)")
	mem := fs.Uint("mem", uint(defMem), "Argon2id memory in MiB")
	fs.UintVar(mem, "m", uint(defMem), "Argon2id memory in MiB (shorthand)")
	par := fs.Uint("par", uint(defPar), "Argon2id parallelism")
	fs.UintVar(par, "p", uint(defPar), "Argon2id parallelism (shorthand)")
	show := fs.Bool("show", false, "reveal the master as you type (private machine only)")
	fs.BoolVar(show, "s", false, "reveal the master as you type (shorthand)")
	file := fileFlag(fs)
	fs.Parse(args)
	flat, blob := cmdPairArg(fs, file)
	_, blobErr := os.Stat(blob)
	_, flatErr := os.Stat(flat)
	if blobErr == nil {
		stem := strings.TrimSuffix(filepath.Base(blob), blobExt)
		die("init: %s already exists — 'nkp unlock %s'?", blob, stem)
	}
	adopt := flatErr == nil
	var body []byte
	if adopt {
		if err := requireRegular(flat, "init: flat"); err != nil {
			die("%v", err)
		}
		data, err := os.ReadFile(flat)
		if err != nil {
			die("init: %v", err)
		}
		if len(data) == 0 {
			die("init: %s is empty — refusing to adopt an empty file", flat)
		}
		// Шапка съедается только своя (blob= совпадает с именем НОВОГО блоба).
		if _, b2 := splitFlat(data, filepath.Base(blob)); b2 != nil && bytes.HasPrefix(data, []byte(flatHdrPrefix)) {
			data = b2
			fmtWarn("init: stale nkp header line consumed")
		}
		body = data
	} else {
		body = []byte(initTemplate)
	}
	readSecret := readPwd
	if *show {
		readSecret = func(prompt string) ([]byte, error) {
			s, err := readLine(prompt)
			return []byte(s), err
		}
	}
	pw, err := readSecret(dbPrompt(blob, "new master: "))
	if err != nil {
		die("password: %v", err)
	}
	if len(pw) == 0 {
		die("master must not be empty")
	}
	pw2, err := readSecret(dbPrompt(blob, "confirm:    "))
	if err != nil {
		die("password: %v", err)
	}
	if !bytes.Equal(pw, pw2) {
		zero(pw)
		zero(pw2)
		die("passwords do not match")
	}
	k := kdfParams{Algorithm: "argon2id", Time: uint32(*t), MemoryMiB: uint32(*mem), Parallelism: uint32(*par)}
	if err := validateKDF(k); err != nil {
		die("init: %v", err)
	}
	if err := sealBlobFile(blob, pw, body, k); err != nil {
		zero(pw)
		zero(pw2)
		die("init: %v", err)
	}
	zero(pw)
	zero(pw2)

	b, err := loadBlobFile(blob)
	if err != nil {
		die("%v", err)
	}
	meta := flatMeta{Blob: filepath.Base(blob), Anchor: anchorOf(b), Body: bodyTag(body)}
	out := append([]byte(flatHeaderLine(meta)+"\n"), body...)
	if err := atomicWrite(flat, out); err != nil {
		zero(out)
		die("write %s: %v", flat, err)
	}
	zero(out)
	zero(body)
	if adopt {
		fmtWarn("initialized %s from existing %s (unlocked — edit, then 'nkp lock')", blob, flat)
	} else {
		fmtWarn("initialized %s (unlocked) — edit %s, then 'nkp lock'", blob, flat)
	}
}

// cmdUnlock: nkp unlock [-f] <file.nkpb>
func cmdUnlock(args []string) {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	force := fs.Bool("f", false, "overwrite an existing flat file")
	file := fileFlag(fs)
	fs.Parse(args)
	flat, blob := cmdPairArg(fs, file)
	b, err := loadBlobFile(blob)
	if err != nil {
		die("%v", err)
	}
	if _, err := os.Stat(flat); err == nil && !*force {
		die("unlock: %s already exists (already unlocked?); -f to discard it", flat)
	}
	pw, err := promptMaster(dbPrompt(blob, "master: "))
	if err != nil {
		die("%v", err)
	}
	defer zero(pw)
	key := blobKeyFrom(pw, b.h.KDF)
	body, err := openBlob(b, key)
	zero(key)
	if err != nil {
		die("decrypt blob failed (wrong master or tampered): %v", err)
	}
	meta := flatMeta{Blob: filepath.Base(blob), Anchor: anchorOf(b), Body: bodyTag(body)}
	out := append([]byte(flatHeaderLine(meta)+"\n"), body...)
	if err := atomicWrite(flat, out); err != nil {
		zero(out)
		zero(body)
		die("write %s: %v", flat, err)
	}
	zero(out)
	zero(body)
	fmtWarn("unlocked → %s", flat)
}

// cmdLock: nkp lock [-f] <file | file.nkpb> | --all
func cmdLock(args []string) {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	force := fs.Bool("f", false, "re-seal even if the blob advanced since unlock")
	all := fs.Bool("all", false, "lock every unlocked base in $NKP_VAULT")
	file := fileFlag(fs)
	fs.Parse(args)
	if *all && fs.NArg() > 0 {
		die("lock --all takes no <name> (it processes everything in $NKP_VAULT)")
	}
	if *all {
		dir := os.Getenv("NKP_VAULT")
		if dir == "" {
			die("lock --all: NKP_VAULT is not set")
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			die("lock --all: %v", err)
		}
		n, failed := 0, 0
		for _, ent := range ents {
			name := ent.Name()
			if ent.IsDir() || !strings.HasSuffix(name, flatExt) {
				continue
			}
			flat := filepath.Join(dir, name)
			blob := strings.TrimSuffix(flat, flatExt) + blobExt
			if _, err := os.Stat(blob); err != nil {
				continue // flat без блоба — не база (init не завершён и т.п.)
			}
			if err := lockOne(flat, blob, *force); err != nil {
				failed++
				fmtWarn("%v", err)
				continue // остальные базы всё равно лочим: plaintext не должен остаться
			}
			n++
		}
		if n == 0 && failed == 0 {
			fmtWarn("lock --all: nothing unlocked in %s", dir)
		}
		if failed > 0 {
			die("lock --all: %d base(s) failed, %d locked — rerun for the failed ones", failed, n)
		}
		return
	}
	flat, blob := cmdPairArg(fs, file)
	if err := lockOne(flat, blob, *force); err != nil {
		die("%v", err)
	}
}

func lockOne(flat, blob string, force bool) error {
	if err := requireRegular(flat, "lock: flat"); err != nil {
		return err
	}
	data, err := os.ReadFile(flat)
	if err != nil {
		return fmt.Errorf("lock: %v (nothing to lock?)", err)
	}
	defer zero(data)
	b, err := loadBlobFile(blob)
	if err != nil {
		return fmt.Errorf("lock: %v — restore the blob (git) or 'nkp init' anew", err)
	}
	meta, body := splitFlat(data, filepath.Base(blob))
	pw, err := promptMaster(dbPrompt(blob, "master: "))
	if err != nil {
		return err
	}
	defer zero(pw)

	// Сверка 1: оригинальный мастер — текущий блоб обязан открываться им.
	key := blobKeyFrom(pw, b.h.KDF)
	blobBody, err := openBlob(b, key)
	zero(key)
	if err != nil {
		return fmt.Errorf("lock: wrong master or blob tampered — nothing was touched")
	}
	defer zero(blobBody)

	if meta != nil {
		// Сверка 2: блоб не уезжал с момента unlock (git pull с другой машины).
		if meta.Anchor != anchorOf(b) {
			// Self-advance: блоб уже содержит ровно наш контент — это краш
			// между seal и wipe, а не гонка: просто убираем flat.
			if bytes.Equal(blobBody, body) {
				wipeFile(flat)
				fmtWarn("locked %s (was already sealed; flat removed)", blob)
				return nil
			}
			if !force {
				return fmt.Errorf("lock: %s changed since unlock — merge manually, or -f to overwrite\n(previous version stays in git history of the blob)", blob)
			}
			fmtWarn("lock: -f: sealing over an advanced blob")
		}
		// Правок нет — запечатывать нечего: убираем только flat.
		if meta.Body == bodyTag(body) {
			wipeFile(flat)
			fmtWarn("locked %s (no changes)", blob)
			return nil
		}
	} else {
		fmtWarn("lock: flat header missing/foreign — sealing without generation check")
	}

	// Пустое тело = вероятный транкейт (ошибка шелла/редактора): без -f отказ.
	if len(body) == 0 && !force {
		return fmt.Errorf("lock: %s is empty — refusing to seal an empty vault (truncate accident?); -f to confirm", flat)
	}

	if err := sealBlobFile(blob, pw, body, b.h.KDF); err != nil {
		return fmt.Errorf("lock: seal: %v", err)
	}
	wipeFile(flat)
	// KDF озвучиваем: тихий downgrade старым блобом (git checkout) становится видимым.
	fmtWarn("locked %s (t=%d mem=%dMiB par=%d)", blob, b.h.KDF.Time, b.h.KDF.MemoryMiB, b.h.KDF.Parallelism)
	return nil
}

// cmdRekey: nkp rekey [-t N -m MiB -p N] [-s] <stem | .txt | .nkpb | dir>
// Смена мастера и/или параметров Argon2id: старый мастер проверяется открытием
// текущего блоба, контент перезапечатывается байт-в-байт (gen+1). Если блоб
// разлочен — правки должны быть закоммичены локом (иначе отказ), flat
// перегенерируется с новой шапкой.
func cmdRekey(args []string) {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	t := fs.Uint("time", uint(defTime), "Argon2id iterations")
	fs.UintVar(t, "t", uint(defTime), "Argon2id iterations (shorthand)")
	mem := fs.Uint("mem", uint(defMem), "Argon2id memory in MiB")
	fs.UintVar(mem, "m", uint(defMem), "Argon2id memory in MiB (shorthand)")
	par := fs.Uint("par", uint(defPar), "Argon2id parallelism")
	fs.UintVar(par, "p", uint(defPar), "Argon2id parallelism (shorthand)")
	show := fs.Bool("show", false, "reveal the new master as you type (private machine only)")
	fs.BoolVar(show, "s", false, "reveal the new master as you type (shorthand)")
	file := fileFlag(fs)
	fs.Parse(args)
	flat, blob := cmdPairArg(fs, file)
	b, err := loadBlobFile(blob)
	if err != nil {
		die("rekey: %v — nothing to rekey", err)
	}
	unlocked := false
	if _, err := os.Stat(flat); err == nil {
		unlocked = true
	}

	oldPw, err := promptMaster(dbPrompt(blob, "old master: "))
	if err != nil {
		die("%v", err)
	}
	key := blobKeyFrom(oldPw, b.h.KDF)
	body, err := openBlob(b, key)
	zero(key)
	zero(oldPw)
	if err != nil {
		die("rekey: wrong master or blob tampered — nothing was touched")
	}
	defer zero(body)

	// Незакоммиченные правки flat при rekey были бы молча потеряны — отказ.
	if unlocked {
		if err := requireRegular(flat, "rekey: flat"); err != nil {
			die("%v", err)
		}
		data, err := os.ReadFile(flat)
		if err != nil {
			die("rekey: %v", err)
		}
		if _, flatBody := splitFlat(data, filepath.Base(blob)); bodyTag(flatBody) != bodyTag(body) {
			die("rekey: %s has uncommitted edits — 'nkp lock' first", flat)
		}
	}

	readSecret := readPwd
	if *show {
		readSecret = func(prompt string) ([]byte, error) {
			s, err := readLine(prompt)
			return []byte(s), err
		}
	}
	pw, err := readSecret(dbPrompt(blob, "new master: "))
	if err != nil {
		die("password: %v", err)
	}
	if len(pw) == 0 {
		die("master must not be empty")
	}
	pw2, err := readSecret(dbPrompt(blob, "confirm:    "))
	if err != nil {
		die("password: %v", err)
	}
	if !bytes.Equal(pw, pw2) {
		zero(pw)
		zero(pw2)
		die("passwords do not match")
	}
	defer zero(pw)
	defer zero(pw2)

	k := kdfParams{Algorithm: "argon2id", Time: uint32(*t), MemoryMiB: uint32(*mem), Parallelism: uint32(*par)}
	if err := validateKDF(k); err != nil {
		die("rekey: %v", err)
	}
	if err := sealBlobFile(blob, pw, body, k); err != nil {
		die("rekey: %v", err)
	}

	if unlocked {
		b2, err := loadBlobFile(blob)
		if err != nil {
			die("%v", err)
		}
		meta := flatMeta{Blob: filepath.Base(blob), Anchor: anchorOf(b2), Body: bodyTag(body)}
		out := append([]byte(flatHeaderLine(meta)+"\n"), body...)
		if err := atomicWrite(flat, out); err != nil {
			zero(out)
			die("write %s: %v", flat, err)
		}
		zero(out)
	}
	fmtWarn("rekeyed %s (t=%d mem=%dMiB par=%d)", blob, *t, *mem, *par)
}

// --- list/show/info для блобов и flat-файлов ---

// cmdList: nkp list <name> | --file <path> — имена секций (flat без мастера).
func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	file := fileFlag(fs)
	fs.Parse(args)
	flat, blob := cmdPairArg(fs, file)
	if p, isFlat := viewPair(flat, blob); isFlat {
		listFlatSections(p, filepath.Base(blob))
	} else {
		listBlobSections(p)
	}
}

// cmdShow: nkp show <name> [<section>] | --file <path> [<section>].
func cmdShow(args []string) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	file := fileFlag(fs)
	fs.Parse(args)
	var flat, blob, sel string
	if *file != "" {
		flat, blob = resolvePair(*file)
		if fs.NArg() > 1 {
			die("show: usage: nkp show --file <path> [<section>]")
		}
		if fs.NArg() == 1 {
			sel = fs.Arg(0)
		}
	} else {
		switch fs.NArg() {
		case 0:
			die("show: missing <name>")
		case 2:
			sel = fs.Arg(1)
		case 1:
		default:
			die("show: usage: nkp show <name> [<section>]")
		}
		flat, blob = resolveBase(fs.Arg(0))
	}
	if p, isFlat := viewPair(flat, blob); isFlat {
		showFlatSections(p, sel, filepath.Base(blob))
	} else {
		showBlobSections(p, sel)
	}
}

// cmdInfo: nkp info <name> | --file <path> — kdf/locked_at/state без мастера.
func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	file := fileFlag(fs)
	fs.Parse(args)
	flat, blob := cmdPairArg(fs, file)
	if _, err := os.Stat(blob); err != nil {
		die("info: no blob at %s", blob)
	}
	infoBlob(blob, flat)
}

func listBlobSections(path string) {
	b, err := loadBlobFile(path)
	if err != nil {
		die("%v", err)
	}
	pw, err := promptMaster(dbPrompt(path, "master: "))
	if err != nil {
		die("%v", err)
	}
	key := blobKeyFrom(pw, b.h.KDF)
	body, err := openBlob(b, key)
	zero(key)
	zero(pw)
	if err != nil {
		die("decrypt blob failed (wrong master?): %v", err)
	}
	_, secs := parseSections(body)
	zero(body)
	printSections(secs)
}

func listFlatSections(path, blobBase string) {
	data, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	_, body := splitFlat(data, blobBase)
	_, secs := parseSections(body)
	printSections(secs)
}

func printSections(secs []section) {
	if len(secs) == 0 {
		fmt.Println("(no sections — file has no '#----[' markers)")
		return
	}
	for i, s := range secs {
		title := s.Title
		if title == "" {
			title = "(untitled)"
		}
		fmt.Printf("  [%d] %s\n", i+1, title)
	}
}

func showBlobSections(path, sel string) {
	b, err := loadBlobFile(path)
	if err != nil {
		die("%v", err)
	}
	pw, err := promptMaster(dbPrompt(path, "master: "))
	if err != nil {
		die("%v", err)
	}
	key := blobKeyFrom(pw, b.h.KDF)
	body, err := openBlob(b, key)
	zero(key)
	zero(pw)
	if err != nil {
		die("decrypt blob failed (wrong master?): %v", err)
	}
	showBody(body, sel, path)
	zero(body)
}

func showFlatSections(path, sel, blobBase string) {
	data, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	_, body := splitFlat(data, blobBase)
	showBody(body, sel, path)
}

// showBody печатает тело целиком (sel == "") или одну секцию с unescape.
func showBody(body []byte, sel, path string) {
	if sel == "" {
		os.Stdout.Write(renderBody(body))
		return
	}
	_, secs := parseSections(body)
	s := findSection(secs, sel)
	if s == nil {
		titles := make([]string, 0, len(secs))
		for _, x := range secs {
			titles = append(titles, x.Title)
		}
		die("no section %q in %s (sections: %s)", sel, path, strings.Join(titles, ", "))
	}
	os.Stdout.Write(renderBody(s.Body))
}

func infoBlob(blob, flat string) {
	b, err := loadBlobFile(blob)
	if err != nil {
		die("%v", err)
	}
	salt, _ := unb64(b.h.KDF.Salt)
	state, age := "locked", ""
	if fi, err := os.Stat(flat); err == nil {
		state = "unlocked"
		d := time.Since(fi.ModTime()).Truncate(time.Minute)
		age = fmt.Sprintf(" (edited %s ago", d)
		if d > warnStaleAfter {
			age += ", ⚠ too long"
		}
		age += ")"
	}
	fmt.Printf("format:        nkp blob\n")
	fmt.Printf("cipher:        %s\n", b.h.Cipher)
	fmt.Printf("KDF:           %s\n", b.h.KDF.Algorithm)
	fmt.Printf("  time:        %d\n", b.h.KDF.Time)
	fmt.Printf("  memory:      %d MiB\n", b.h.KDF.MemoryMiB)
	fmt.Printf("  parallelism: %d\n", b.h.KDF.Parallelism)
	fmt.Printf("salt:          %x\n", salt)
	lockedAt := b.h.LockedAt
	if lockedAt == "" {
		lockedAt = "unknown"
	}
	fmt.Printf("locked_at:     %s\n", lockedAt)
	fmt.Printf("state:         %s%s\n", state, age)
	fmt.Printf("ct size:       %d bytes\n", len(b.ct))
}
