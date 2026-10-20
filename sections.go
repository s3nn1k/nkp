// sections.go — разбор плоского файла на секции (для list/show в blob-режиме).
//
// Маркер секции — точный литерал sectionPrefix в колонке 0. Всё остальное —
// контент, включая любые другие '#'-строки. Строке тела, которой нужен сам
// литерал, он пишется с обратным слэшем; renderBody снимает его при показе
// (в файле/блобе экранирование хранится как есть).
package main

import (
	"bytes"
	"strings"
)

const sectionPrefix = "#----["

type section struct {
	Title string
	Body  []byte // от конца строки-маркера до начала следующего маркера или EOF
}

// parseSections делит body на преамбулу (до первого маркера) и секции.
// Побайтово точно: тела включают все пустые строки и финальный фрагмент как есть.
func parseSections(body []byte) (preamble []byte, secs []section) {
	type mark struct {
		title  string
		start  int // offset строки-маркера
		bodyAt int // offset сразу после неё (за '\n')
	}
	var marks []mark
	off := 0
	for off < len(body) {
		nl := bytes.IndexByte(body[off:], '\n')
		lineEnd := len(body)
		if nl >= 0 {
			lineEnd = off + nl
		}
		if bytes.HasPrefix(body[off:lineEnd], []byte(sectionPrefix)) {
			bodyAt := lineEnd + 1
			if bodyAt > len(body) { // маркер без завершающего '\n'
				bodyAt = len(body)
			}
			marks = append(marks, mark{title: sectionTitle(body[off:lineEnd]), start: off, bodyAt: bodyAt})
		}
		if nl < 0 {
			break
		}
		off = lineEnd + 1
	}
	if len(marks) == 0 {
		return body, nil
	}
	preamble = body[:marks[0].start]
	for i, m := range marks {
		end := len(body)
		if i+1 < len(marks) {
			end = marks[i+1].start
		}
		secs = append(secs, section{Title: m.title, Body: body[m.bodyAt:end]})
	}
	return preamble, secs
}

// sectionTitle: "#----[ postgres/all ]" -> "postgres/all".
func sectionTitle(line []byte) string {
	t := strings.TrimSpace(string(line[len(sectionPrefix):]))
	t = strings.TrimSuffix(t, "]")
	return strings.TrimSpace(t)
}

// findSection ищет секцию по точному имени.
func findSection(secs []section, title string) *section {
	for i := range secs {
		if secs[i].Title == title {
			return &secs[i]
		}
	}
	return nil
}

// renderBody готовит тело к показу: строка "\#----[…" печатается как "#----[…".
// Обратный слэш снимается только перед зарезервированным литералом.
func renderBody(body []byte) []byte {
	if !bytes.Contains(body, []byte("\\#----[")) {
		return body
	}
	var out bytes.Buffer
	off := 0
	for off < len(body) {
		nl := bytes.IndexByte(body[off:], '\n')
		end := len(body)
		if nl >= 0 {
			end = off + nl
		}
		line := body[off:end]
		if bytes.HasPrefix(line, []byte("\\#----[")) {
			line = line[1:]
		}
		out.Write(line)
		if nl >= 0 {
			out.WriteByte('\n')
		} else {
			break
		}
		off = end + 1
	}
	return out.Bytes()
}
