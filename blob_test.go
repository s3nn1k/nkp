// blob_test.go — тесты blob-режима: крипто-цикл, шапка flat-файла, секции,
// escape и end-to-end через собранный бинарник (быстрый KDF, NKP_VAULT во temp).
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKDF() kdfParams {
	return kdfParams{Algorithm: "argon2id", Time: 1, MemoryMiB: 8, Parallelism: 1}
}

// sampleFlat: преамбула, три секции, многострочность, #-контент, escape,
// последняя строка без завершающего перевода строки.
const sampleFlat = "preamble line\n" +
	"#----[ postgres/all ]\n" +
	"password:\n" +
	"  multi#line\n" +
	"  ## double hash\n" +
	"\n" +
	"#----[ cf ]\n" +
	"tok#en-with-#hashes\n" +
	"\\#----[ escaped literal marker\n" +
	"plain tail\n" +
	"#----[ empty ]\n" +
	"\n" +
	"last"

// --- юнит-тесты ---

func TestSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	blob := filepath.Join(dir, "work.nkpb")
	pw := []byte("master-pass")
	if err := sealBlobFile(blob, pw, []byte(sampleFlat), testKDF()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b, err := loadBlobFile(blob)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.h.Cipher != cipherName || b.h.LockedAt == "" {
		t.Fatalf("header = %+v", b.h)
	}
	body, err := openBlob(b, blobKeyFrom(pw, b.h.KDF))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(body, []byte(sampleFlat)) {
		t.Fatalf("round-trip mismatch:\n%q\n%q", body, sampleFlat)
	}
}

func TestWrongMaster(t *testing.T) {
	dir := t.TempDir()
	blob := filepath.Join(dir, "w.nkpb")
	if err := sealBlobFile(blob, []byte("right"), []byte("x"), testKDF()); err != nil {
		t.Fatal(err)
	}
	b, _ := loadBlobFile(blob)
	if _, err := openBlob(b, blobKeyFrom([]byte("wrong"), b.h.KDF)); err == nil {
		t.Fatal("wrong master must not open")
	}
}

func TestFreshSaltEachSeal(t *testing.T) {
	dir := t.TempDir()
	pw := []byte("m")
	b1 := filepath.Join(dir, "a.nkpb")
	b2 := filepath.Join(dir, "b.nkpb")
	sealBlobFile(b1, pw, []byte("same"), testKDF())
	sealBlobFile(b2, pw, []byte("same"), testKDF())
	x1, _ := loadBlobFile(b1)
	x2, _ := loadBlobFile(b2)
	if bytes.Equal(x1.aad, x2.aad) {
		t.Fatal("same body must not produce identical ciphertext/headers")
	}
	if anchorOf(x1) == anchorOf(x2) {
		t.Fatal("anchors must differ (fresh salt+nonce)")
	}
}

func TestFlatHeaderCycle(t *testing.T) {
	dir := t.TempDir()
	blob := filepath.Join(dir, "work.nkpb")
	if err := sealBlobFile(blob, []byte("m"), []byte(sampleFlat), testKDF()); err != nil {
		t.Fatal(err)
	}
	b, _ := loadBlobFile(blob)
	meta := flatMeta{Blob: "work.nkpb", Anchor: anchorOf(b), Body: bodyTag([]byte(sampleFlat))}
	out := append([]byte(flatHeaderLine(meta)+"\n"), []byte(sampleFlat)...)

	m, body := splitFlat(out, "work.nkpb")
	if m == nil || m.Anchor != anchorOf(b) {
		t.Fatalf("header not parsed: %+v", m)
	}
	if !bytes.Equal(body, []byte(sampleFlat)) {
		t.Fatal("body mismatch after header split")
	}
	if m2, _ := splitFlat(out, "other.nkpb"); m2 != nil {
		t.Fatal("header for another blob must be treated as content")
	}
	if m3, body3 := splitFlat([]byte(sampleFlat), "work.nkpb"); m3 != nil || !bytes.Equal(body3, []byte(sampleFlat)) {
		t.Fatal("file without header must pass through as body")
	}
}

// Старая шапка (с gen=) всё ещё опознаётся — неизвестные поля игнорируются.
func TestFlatHeaderLegacyGen(t *testing.T) {
	dir := t.TempDir()
	blob := filepath.Join(dir, "work.nkpb")
	sealBlobFile(blob, []byte("m"), []byte(sampleFlat), testKDF())
	b, _ := loadBlobFile(blob)
	legacy := "# nkp:v1 blob=work.nkpb gen=7 anchor=" + anchorOf(b) + " body=" + bodyTag([]byte(sampleFlat)) + "\n"
	out := append([]byte(legacy), []byte(sampleFlat)...)
	m, body := splitFlat(out, "work.nkpb")
	if m == nil || !bytes.Equal(body, []byte(sampleFlat)) {
		t.Fatal("legacy header (gen=) must still be recognized")
	}
}

func TestSections(t *testing.T) {
	preamble, secs := parseSections([]byte(sampleFlat))
	if string(preamble) != "preamble line\n" {
		t.Fatalf("preamble = %q", preamble)
	}
	want := []string{"postgres/all", "cf", "empty"}
	if len(secs) != len(want) {
		t.Fatalf("sections = %+v", secs)
	}
	for i, w := range want {
		if secs[i].Title != w {
			t.Fatalf("title[%d] = %q, want %q", i, secs[i].Title, w)
		}
	}
	if !bytes.Equal(secs[0].Body, []byte("password:\n  multi#line\n  ## double hash\n\n")) {
		t.Fatalf("body[0] = %q", secs[0].Body)
	}
	if !bytes.Equal(secs[1].Body, []byte("tok#en-with-#hashes\n\\#----[ escaped literal marker\nplain tail\n")) {
		t.Fatalf("body[1] = %q", secs[1].Body)
	}
	if !bytes.Equal(secs[2].Body, []byte("\nlast")) {
		t.Fatalf("body[2] = %q", secs[2].Body)
	}
}

func TestRenderBodyEscape(t *testing.T) {
	in := []byte("a\n\\#----[ literal\nb\n")
	want := []byte("a\n#----[ literal\nb\n")
	if !bytes.Equal(renderBody(in), want) {
		t.Fatalf("renderBody = %q", renderBody(in))
	}
	if !bytes.Equal(renderBody([]byte("no escapes")), []byte("no escapes")) {
		t.Fatal("fast path must not copy")
	}
}

func TestSectionTitle(t *testing.T) {
	cases := map[string]string{
		"#----[ a ]":        "a",
		"#----[ a":          "a",
		"#----[  spaced  ]": "spaced",
		"#----[ array[0] ]": "array[0]", // внутренние скобки — часть имени
		"#----[ a] ]":       "a]",       // имя, заканчивающееся на ], требует явной пары
		"#----[ a ]]":       "a ]",      // срезается ровно одна завершающая ]
		"#----[ array[0]":   "array[0",  // последняя ] без пары считается закрывающей
		"#----[ ]":          "",         // untitled
	}
	for line, want := range cases {
		if got := sectionTitle([]byte(line)); got != want {
			t.Fatalf("sectionTitle(%q) = %q, want %q", line, got, want)
		}
	}
}

// --- end-to-end через собранный бинарник ---

type harness struct {
	bin string
	db  string // $NKP_VAULT
}

func newH(t *testing.T) *harness {
	return &harness{bin: buildBin(t), db: t.TempDir()}
}

func (h *harness) run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(h.bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "NKP_VAULT="+h.db)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "nkp-e2e")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestE2EBlobCycle(t *testing.T) {
	h := newH(t)
	flat := filepath.Join(h.db, "work.txt")
	blob := filepath.Join(h.db, "work.nkpb")

	// init с существующим .txt — адаптация: блоб создан, flat остался разлоченным
	if err := os.WriteFile(flat, []byte(sampleFlat), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "work"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if _, err := os.Stat(blob); err != nil {
		t.Fatal("blob must exist after init")
	}
	if _, err := os.Stat(flat); err != nil {
		t.Fatal("flat must stay after init (adopted, unlocked)")
	}
	if out, _ := h.run(t, "", "info", "work"); !strings.Contains(out, "state:         unlocked") || !strings.Contains(out, "locked_at:") {
		t.Fatalf("info after init:\n%s", out)
	}
	data := mustRead(t, flat)
	if m, body := splitFlat(data, "work.nkpb"); m == nil || !bytes.Equal(body, []byte(sampleFlat)) {
		t.Fatalf("flat header/body bad: %q", data[:80])
	}

	// list/show на flat без мастера
	if out, err := h.run(t, "", "list", "work"); err != nil || !strings.Contains(out, "postgres/all") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if out, err := h.run(t, "", "show", "work", "cf"); err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	} else if out != "tok#en-with-#hashes\n#----[ escaped literal marker\nplain tail\n" {
		t.Fatalf("show output: %q", out)
	}

	// правка + lock с неверным мастером: отказ, файлы не тронуты
	if err := os.WriteFile(flat, append(data, []byte("\n#----[ extra ]\nnew secret\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := h.run(t, "nope\n", "lock", "work"); err == nil {
		t.Fatalf("lock with wrong master must fail:\n%s", out)
	}
	if _, err := os.Stat(flat); err != nil {
		t.Fatal("flat must survive failed lock")
	}

	// правильный lock: flat вытерт; show из блоба one-shot с мастером
	if out, err := h.run(t, "m\n", "lock", "work"); err != nil {
		t.Fatalf("lock: %v\n%s", err, out)
	}
	if _, err := os.Stat(flat); !os.IsNotExist(err) {
		t.Fatal("flat must be wiped after lock")
	}
	if out, _ := h.run(t, "", "info", "work"); !strings.Contains(out, "state:         locked") {
		t.Fatalf("info after lock:\n%s", out)
	}
	if out, err := h.run(t, "m\n", "show", "work", "extra"); err != nil || out != "new secret\n" {
		t.Fatalf("one-shot show from locked blob: %v %q", err, out)
	}
	// неверный мастер на one-shot — отказ
	if out, err := h.run(t, "bad\n", "show", "work", "cf"); err == nil {
		t.Fatalf("one-shot with wrong master must fail:\n%s", out)
	}

	// unlock: тело = отредактированное (без шапки)
	if out, err := h.run(t, "m\n", "unlock", "work"); err != nil {
		t.Fatalf("unlock: %v\n%s", err, out)
	}
	if _, body := splitFlat(mustRead(t, flat), "work.nkpb"); !bytes.Equal(body, append([]byte(sampleFlat), []byte("\n#----[ extra ]\nnew secret\n")...)) {
		t.Fatal("edited body mismatch")
	}

	// lock без правок: перезапечатки нет (locked_at не меняется)
	before := func() string {
		b, _ := loadBlobFile(blob)
		return b.h.LockedAt
	}()
	if out, err := h.run(t, "m\n", "lock", "work"); err != nil {
		t.Fatalf("lock#2: %v\n%s", err, out)
	}
	if after := func() string {
		b, _ := loadBlobFile(blob)
		return b.h.LockedAt
	}(); after != before {
		t.Fatalf("no-change lock must not re-seal: %s -> %s", before, after)
	}
}

func TestE2EInitFresh(t *testing.T) {
	h := newH(t)
	if out, err := h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "fresh"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	flat, blob := filepath.Join(h.db, "fresh.txt"), filepath.Join(h.db, "fresh.nkpb")
	data := mustRead(t, flat)
	if m, body := splitFlat(data, "fresh.nkpb"); m == nil || !bytes.Contains(body, []byte("#----[ example ]")) {
		t.Fatalf("fresh flat must carry header + template: %q", data)
	}
	if out, err := h.run(t, "", "list", "fresh"); err != nil || !strings.Contains(out, "example") {
		t.Fatalf("list on fresh template: %v\n%s", err, out)
	}
	if out, err := h.run(t, "m\n", "lock", "fresh"); err != nil {
		t.Fatalf("lock fresh: %v\n%s", err, out)
	}
	if b, err := loadBlobFile(blob); err != nil || b.h.LockedAt == "" {
		t.Fatalf("blob after lock: %v %+v", err, b.h)
	}
}

func TestE2ERaceDetection(t *testing.T) {
	h := newH(t)
	flat := filepath.Join(h.db, "r.txt")
	blob := filepath.Join(h.db, "r.nkpb")
	os.WriteFile(flat, []byte("#----[ a ]\n1\n"), 0600)
	if out, err := h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "r"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	// блоб "уехал" (git pull с другой машины): перезапечатываем напрямую
	if err := sealBlobFile(blob, []byte("m"), []byte("#----[ a ]\nnewer\n"), testKDF()); err != nil {
		t.Fatal(err)
	}
	if out, err := h.run(t, "m\n", "lock", "r"); err == nil {
		t.Fatalf("race must be detected:\n%s", out)
	}
	if _, err := os.Stat(flat); err != nil {
		t.Fatal("flat must survive race refusal")
	}
	if out, err := h.run(t, "m\n", "lock", "-f", "r"); err != nil {
		t.Fatalf("lock -f: %v\n%s", err, out)
	}
}

func TestE2EHeaderLoss(t *testing.T) {
	h := newH(t)
	flat := filepath.Join(h.db, "h.txt")
	os.WriteFile(flat, []byte("#----[ a ]\nsecret\n"), 0600)
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "h")
	// пользователь удалил шапку
	_, body := splitFlat(mustRead(t, flat), "h.nkpb")
	os.WriteFile(flat, body, 0600)
	// lock проходит (сверка мастера не зависит от шапки), тело сохраняется
	if out, err := h.run(t, "m\n", "lock", "h"); err != nil {
		t.Fatalf("lock after header loss: %v\n%s", err, out)
	}
	h.run(t, "m\n", "unlock", "h")
	if _, body2 := splitFlat(mustRead(t, flat), "h.nkpb"); !bytes.Equal(body2, body) {
		t.Fatal("body must survive header-loss cycle")
	}
}

func TestE2ERekey(t *testing.T) {
	h := newH(t)
	flat := filepath.Join(h.db, "k.txt")
	os.WriteFile(flat, []byte("#----[ a ]\nsecret\n"), 0600)
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "k")

	// неверный старый мастер — отказ
	if out, err := h.run(t, "bad\nx\nx\n", "rekey", "-m", "8", "-t", "1", "-p", "1", "k"); err == nil {
		t.Fatalf("rekey with wrong old master must fail:\n%s", out)
	}
	// незакоммиченные правки — отказ
	os.WriteFile(flat, append(mustRead(t, flat), []byte("\n#----[ b ]\n2\n")...), 0600)
	if out, err := h.run(t, "m\nn\nn\n", "rekey", "-m", "8", "-t", "1", "-p", "1", "k"); err == nil {
		t.Fatalf("rekey with uncommitted edits must fail:\n%s", out)
	}
	// фиксируем правки локом, rekey на залоченном: m -> n
	h.run(t, "m\n", "lock", "k")
	if out, err := h.run(t, "m\nn\nn\n", "rekey", "-m", "16", "-t", "1", "-p", "1", "k"); err != nil {
		t.Fatalf("rekey: %v\n%s", err, out)
	}
	if out, _ := h.run(t, "", "info", "k"); !strings.Contains(out, "memory:      16 MiB") {
		t.Fatalf("info after rekey:\n%s", out)
	}
	// старый мастер больше не открывает, новый открывает, контент цел
	if out, err := h.run(t, "m\n", "unlock", "k"); err == nil {
		t.Fatalf("old master must not unlock after rekey:\n%s", out)
	}
	if out, err := h.run(t, "n\n", "unlock", "k"); err != nil {
		t.Fatalf("unlock after rekey: %v\n%s", err, out)
	}
	if _, body := splitFlat(mustRead(t, flat), "k.nkpb"); !bytes.Equal(body, []byte("#----[ a ]\nsecret\n\n#----[ b ]\n2\n")) {
		t.Fatalf("content must survive rekey: %q", body)
	}
	// rekey на разлоченном без правок: состояние сохранено
	if out, err := h.run(t, "n\nn2\nn2\n", "rekey", "-m", "8", "-t", "1", "-p", "1", "k"); err != nil {
		t.Fatalf("rekey unlocked: %v\n%s", err, out)
	}
	if out, _ := h.run(t, "", "info", "k"); !strings.Contains(out, "state:         unlocked") {
		t.Fatalf("info after unlocked rekey:\n%s", out)
	}
	if out, err := h.run(t, "n2\n", "lock", "k"); err != nil {
		t.Fatalf("lock with newest master: %v\n%s", err, out)
	}
}

func TestE2ELockAll(t *testing.T) {
	h := newH(t)
	for _, name := range []string{"s", "t"} {
		os.WriteFile(filepath.Join(h.db, name+flatExt), []byte("#----[ a ]\n1\n"), 0600)
		if out, err := h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", name); err != nil {
			t.Fatalf("init %s: %v\n%s", name, err, out)
		}
	}
	if out, err := h.run(t, "m\nm\n", "lock", "--all"); err != nil {
		t.Fatalf("lock --all: %v\n%s", err, out)
	}
	for _, name := range []string{"s", "t"} {
		if _, err := os.Stat(filepath.Join(h.db, name+flatExt)); !os.IsNotExist(err) {
			t.Fatalf("%s.txt must be wiped by lock --all", name)
		}
		if out, _ := h.run(t, "", "info", name); !strings.Contains(out, "state:         locked") {
			t.Fatalf("info %s after --all:\n%s", name, out)
		}
	}
}

// TestE2EFileFlag: сырые пути вне $NKP_VAULT — только через --file.
func TestE2EFileFlag(t *testing.T) {
	h := newH(t)
	outdir := t.TempDir()
	flat := filepath.Join(outdir, "side.txt")
	blob := filepath.Join(outdir, "side.nkpb")
	os.WriteFile(flat, []byte("#----[ x ]\ny\n"), 0600)

	if out, err := h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "--file", flat); err != nil {
		t.Fatalf("init --file: %v\n%s", err, out)
	}
	if _, err := os.Stat(blob); err != nil {
		t.Fatal("blob must be created next to the flat")
	}
	h.run(t, "m\n", "lock", "--file", flat)
	if out, err := h.run(t, "m\n", "show", "--file", blob, "x"); err != nil || out != "y\n" {
		t.Fatalf("show --file: %v %q\n%s", err, out, out)
	}
	if out, err := h.run(t, "m\n", "unlock", "--file", blob); err != nil {
		t.Fatalf("unlock --file: %v\n%s", err, out)
	}
	// файл-подобный позиционный аргумент без --file — отказ с подсказкой
	if out, err := h.run(t, "", "unlock", "./side"); err == nil || !strings.Contains(out, "--file") {
		t.Fatalf("file-ish positional must be refused with a --file hint:\n%s", out)
	}
	// без NKP_VAULT имя не резолвится
	cmd := exec.Command(h.bin, "list", "work")
	cmd.Env = append(os.Environ(), "NKP_VAULT=")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err == nil || !strings.Contains(out.String(), "NKP_VAULT") {
		t.Fatalf("missing NKP_VAULT must fail with a hint:\n%s", out.String())
	}
}

// --- регрессии по адверсальному ревью ---

// П.1: lock --all не умирает на первой базе — остальные лочит, exit != 0.
func TestLockAllPartialFailure(t *testing.T) {
	h := newH(t)
	for _, name := range []string{"s", "t"} {
		os.WriteFile(filepath.Join(h.db, name+flatExt), []byte("#----[ a ]\n1\n"), 0600)
		h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", name)
	}
	// неверный мастер для s, верный для t
	if out, err := h.run(t, "bad\nm\n", "lock", "--all"); err == nil {
		t.Fatalf("--all must exit non-zero on partial failure:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.db, "s"+flatExt)); err != nil {
		t.Fatal("failed base must stay unlocked")
	}
	if _, err := os.Stat(filepath.Join(h.db, "t"+flatExt)); !os.IsNotExist(err) {
		t.Fatal("healthy base must still be locked")
	}
}

// П.2: симлинк вместо flat — отказ, жертва не тронута.
func TestSymlinkFlatRefused(t *testing.T) {
	h := newH(t)
	victim := filepath.Join(t.TempDir(), "victim.txt")
	os.WriteFile(victim, []byte("VICTIM-IMPORTANT"), 0600)
	os.WriteFile(filepath.Join(h.db, "v.nkpb"), nil, 0600) // заглушка-блоб не нужна; создадим базу:
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "v")
	h.run(t, "m\n", "lock", "v")
	os.Remove(filepath.Join(h.db, "v"+flatExt))
	os.Symlink(victim, filepath.Join(h.db, "v"+flatExt))
	if out, err := h.run(t, "m\n", "lock", "v"); err == nil || !strings.Contains(out, "symlink") {
		t.Fatalf("lock must refuse a symlinked flat:\n%s", out)
	}
	if got := mustRead(t, victim); !bytes.Equal(got, []byte("VICTIM-IMPORTANT")) {
		t.Fatalf("victim damaged: %q", got)
	}
}

// П.3: застрявший .nkp-tmp-* вычищается, свежий — нет.
func TestTmpSweep(t *testing.T) {
	h := newH(t)
	stale := filepath.Join(h.db, ".nkp-tmp-stale")
	fresh := filepath.Join(h.db, ".nkp-tmp-fresh")
	os.WriteFile(stale, []byte("plaintext-leftover"), 0600)
	os.WriteFile(fresh, []byte("in-flight"), 0600)
	old := time.Now().Add(-2 * time.Minute)
	os.Chtimes(stale, old, old)
	h.run(t, "", "info", "nope") // любая команда заметает каталог
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp must be swept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh temp must survive (parallel process)")
	}
}

// П.4: чужая шапка — контент, не съедается show.
func TestForeignHeaderNotConsumed(t *testing.T) {
	h := newH(t)
	os.WriteFile(filepath.Join(h.db, "z.txt"), []byte("# nkp:v1 blob=OTHER.nkpb anchor=abcdefabcdef body=1234567890ab\nSECRET-FIRST-LINE\n"), 0600)
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "z")
	if out, err := h.run(t, "", "show", "z"); err != nil || !strings.Contains(out, "SECRET-FIRST-LINE") {
		t.Fatalf("foreign header must be shown as content: %v\n%s", err, out)
	}
	// и запечатывается как контент (после unlock первая строка тела — та же шапка)
	h.run(t, "m\n", "lock", "z")
	h.run(t, "m\n", "unlock", "z")
	data := mustRead(t, filepath.Join(h.db, "z.txt"))
	_, body := splitFlat(data, "z.nkpb")
	if !bytes.HasPrefix(body, []byte("# nkp:v1 blob=OTHER.nkpb")) {
		t.Fatalf("foreign header must be sealed as content: %q", body[:min(60, len(body))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// П.5: транкейт -> пустое тело: lock отказывает без -f.
func TestEmptySealRefused(t *testing.T) {
	h := newH(t)
	os.WriteFile(filepath.Join(h.db, "e.txt"), []byte("#----[ a ]\n1\n"), 0600)
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "e")
	os.WriteFile(filepath.Join(h.db, "e.txt"), nil, 0600) // > e.txt
	if out, err := h.run(t, "m\n", "lock", "e"); err == nil || !strings.Contains(out, "empty") {
		t.Fatalf("empty seal must be refused:\n%s", out)
	}
	if out, err := h.run(t, "m\n", "lock", "-f", "e"); err != nil {
		t.Fatalf("-f must override: %v\n%s", err, out)
	}
}

// П.6: имя базы с пробелом/'=' отклоняется.
func TestBadBaseName(t *testing.T) {
	h := newH(t)
	if out, err := h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "my base"); err == nil || !strings.Contains(out, "spaces") {
		t.Fatalf("space name must be rejected:\n%s", out)
	}
}

// П.8: крафтовые KDF-заголовки — чистый отказ, не panic.
func TestCraftedKDFHeader(t *testing.T) {
	h := newH(t)
	blob := filepath.Join(h.db, "c.nkpb")
	if err := sealBlobFile(blob, []byte("m"), []byte("x"), testKDF()); err != nil {
		t.Fatal(err)
	}
	data := mustRead(t, blob)
	nl := bytes.IndexByte(data[len(blobMagicStr):], '\n')
	ct := data[nl+1+len(blobMagicStr):]
	for _, hdr := range []string{
		`{"kdf":{"algorithm":"argon2id","salt":"AAAA","time":0,"memory_mib":8,"parallelism":1},"cipher":"xchacha20-poly1305","nonce":"BBBB"}`,
		`{"kdf":{"algorithm":"argon2id","salt":"AAAA","time":1,"memory_mib":8,"parallelism":256},"cipher":"xchacha20-poly1305","nonce":"BBBB"}`,
		`{"kdf":{"algorithm":"argon2id","salt":"AAAA","time":1,"memory_mib":999999,"parallelism":1},"cipher":"xchacha20-poly1305","nonce":"BBBB"}`,
	} {
		out := append([]byte(blobMagicStr), []byte(hdr+"\n")...)
		out = append(out, ct...)
		os.WriteFile(blob, out, 0600)
		if res, err := h.run(t, "", "info", "c"); err == nil || !strings.Contains(res, "range") {
			t.Fatalf("crafted KDF must die cleanly:\n%s", res)
		}
	}
}

// П.8b: init -t 0 — чистый отказ.
func TestInitBadFlags(t *testing.T) {
	h := newH(t)
	if out, err := h.run(t, "m\nm\n", "init", "-t", "0", "-m", "8", "-p", "1", "x"); err == nil || !strings.Contains(out, "range") {
		t.Fatalf("init -t 0 must die cleanly:\n%s", out)
	}
}

// Пустой мастер отклоняется.
func TestEmptyMaster(t *testing.T) {
	h := newH(t)
	if out, err := h.run(t, "\n\n", "init", "-t", "1", "-m", "8", "-p", "1", "x"); err == nil || !strings.Contains(out, "not be empty") {
		t.Fatalf("empty master must be rejected:\n%s", out)
	}
}

// П.9: self-advance (краш после seal до wipe) — не «гонка», просто wipe.
func TestSelfAdvanceWipe(t *testing.T) {
	h := newH(t)
	flat := filepath.Join(h.db, "a.txt")
	blob := filepath.Join(h.db, "a.nkpb")
	os.WriteFile(flat, []byte("#----[ x ]\ny\n"), 0600)
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "a")
	_, body := splitFlat(mustRead(t, flat), "a.nkpb")
	// «краш»: блоб перезапечатан тем же контентом, flat остался
	sealBlobFile(blob, []byte("m"), body, testKDF())
	if out, err := h.run(t, "m\n", "lock", "a"); err != nil {
		t.Fatalf("self-advance must lock cleanly:\n%s", out)
	} else if !strings.Contains(out, "already sealed") {
		t.Fatalf("unexpected message:\n%s", out)
	}
	if _, err := os.Stat(flat); !os.IsNotExist(err) {
		t.Fatal("flat must be wiped")
	}
}

// П.5(п shade): lock озвучивает KDF (видимый downgrade).
func TestLockReportsKDF(t *testing.T) {
	h := newH(t)
	os.WriteFile(filepath.Join(h.db, "k.txt"), []byte("#----[ a ]\n1\n"), 0600)
	h.run(t, "m\nm\n", "init", "-t", "1", "-m", "8", "-p", "1", "k")
	h.run(t, "m\n", "lock", "k")
	h.run(t, "m\n", "unlock", "k")
	os.WriteFile(filepath.Join(h.db, "k.txt"), []byte("#----[ a ]\n1\n#----[ b ]\n2\n"), 0600)
	if out, err := h.run(t, "m\n", "lock", "k"); err != nil || !strings.Contains(out, "t=1 mem=8MiB") {
		t.Fatalf("lock must report KDF params:\n%s", out)
	}
}
