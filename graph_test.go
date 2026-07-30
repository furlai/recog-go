package recog

import (
	"fmt"
	"testing"
)

// benchCorpus is a set of banner-like strings shaped like the traversal's
// production inputs (vendor/product titles with versions). LoadFingerprints
// loads the embedded recog databases, so matches exercise the real regex sets.
func benchCorpus() []string {
	out := make([]string, 200)
	for i := range out {
		out[i] = fmt.Sprintf("Apache/2.4.%d (Ubuntu) OpenSSL/1.1.1%c", i%60, 'a'+rune(i%20))
	}
	return out
}

// TestTraverseMatchNodeIDsAreUniqueAndLinked pins the property the id
// generator must preserve: every node id is unique within one traversal, and
// every edge's parent/child ids reference nodes from that same traversal —
// the exact invariants a consumer of the (nodes, edges) graph relies on,
// independent of HOW ids are minted (uuid.New before, a traversal-local
// counter now).
func TestTraverseMatchNodeIDsAreUniqueAndLinked(t *testing.T) {
	fset, err := LoadFingerprints()
	if err != nil {
		t.Fatalf("LoadFingerprints() failed: %s", err)
	}
	nodes, edges, err := TraverseMatch(fset, "http_header.server", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f")
	if err != nil {
		t.Fatalf("TraverseMatch failed: %s", err)
	}
	if len(nodes) == 0 {
		t.Skip("corpus produced no matches; fingerprint dbs changed shape")
	}
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		key := n.Id.String()
		if seen[key] {
			t.Fatalf("duplicate node id within one traversal: %s", key)
		}
		seen[key] = true
	}
	for _, e := range edges {
		if !seen[e.ParentId.String()] || !seen[e.ChildId.String()] {
			t.Fatalf("edge references a node id not in this traversal's node set: %v", e)
		}
	}
}

// BenchmarkTraverseMatch measures single-caller traversal cost — the number
// the traversal-local id generator improves (uuid.New() previously cost one
// entropy syscall per matched node). Compare across branches with benchstat.
func BenchmarkTraverseMatch(b *testing.B) {
	fset, err := LoadFingerprints()
	if err != nil {
		b.Fatalf("LoadFingerprints() failed: %s", err)
	}
	corpus := benchCorpus()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = TraverseMatch(fset, "http_header.server", corpus[i%len(corpus)])
	}
}

// BenchmarkTraverseMatchParallel measures contended traversal — the case the
// per-node entropy syscall serialized (kernel entropy reads are effectively a
// global lock), which is how the cost was found in production profiling.
func BenchmarkTraverseMatchParallel(b *testing.B) {
	fset, err := LoadFingerprints()
	if err != nil {
		b.Fatalf("LoadFingerprints() failed: %s", err)
	}
	corpus := benchCorpus()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _, _ = TraverseMatch(fset, "http_header.server", corpus[i%len(corpus)])
			i++
		}
	})
}
