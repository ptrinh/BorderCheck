package checks

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// A chat-like text: JSON lines of prose, code, URLs and paths, no secrets.
func chatLike(n int) []byte {
	words := strings.Fields(`the task-runner disk-encryption https://example.com/a/b ask-me password: str ` +
		`func main() { fmt.Println("hello") } import os sk-learn ~/.claude/projects risk-free {"type":"tool_result"} ` +
		`AKIA is a prefix ghp_ is too npm_install AIza http://localhost:8080/x user@example.com /usr/local/bin`)
	r := rand.New(rand.NewSource(1))
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(`{"type":"assistant","message":{"content":"`)
		for range 200 {
			b.WriteString(words[r.Intn(len(words))])
			b.WriteByte(' ')
		}
		b.WriteString("\"}}\n")
	}
	return []byte(b.String())
}

func BenchmarkScanChat(b *testing.B) {
	p := policy.Default().Checks.Secrets
	s, err := newSecretScanner(p, "/home/an")
	if err != nil {
		b.Fatal(err)
	}
	data := chatLike(32 << 20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		s.scanChat(data, "~/x.jsonl", true, nil)
	}
}
