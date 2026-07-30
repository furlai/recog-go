package recog

import (
	"encoding/binary"

	"github.com/google/uuid"
)

type MatchNode struct {
	Id    uuid.UUID
	Match *FingerprintMatch
}

type MatchEdge struct {
	ParentId uuid.UUID
	ChildId  uuid.UUID
}

// nodeIDGen mints traversal-local node ids without touching the system
// entropy pool. uuid.New() costs one getrandom/getentropy syscall per id —
// profiled as the dominant cost of match traversal under load on hosts with
// expensive entropy reads — and these ids only need to be unique within one
// traversal's node/edge graph, never globally. The counter is embedded in a
// UUID-shaped value so the public MatchNode/MatchEdge API is unchanged.
type nodeIDGen uint64

func (g *nodeIDGen) next() uuid.UUID {
	*g++
	var u uuid.UUID
	binary.BigEndian.PutUint64(u[8:], uint64(*g))
	u[6] = (u[6] & 0x0f) | 0x40 // keep RFC 4122 version/variant shape
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func TraverseMatch(fpset *FingerprintSet, dbtype string, text string) ([]*MatchNode, []*MatchEdge, error) {
	var gen nodeIDGen
	return traverseMatch(nil, &gen, fpset, dbtype, text)
}

// Recursively match against the fingerprint database.
func traverseMatch(parentId *uuid.UUID, gen *nodeIDGen, fpset *FingerprintSet, dbtype string, text string) ([]*MatchNode, []*MatchEdge, error) {
	var nodes []*MatchNode
	var edges []*MatchEdge

	// no matches? return nil now
	fps, err := fpset.MatchAll(dbtype, text)
	if err != nil {
		return nil, nil, err
	}

	// iterate over the matches and construct the graph from the results
	for _, fpMatch := range fps {
		node := &MatchNode{Id: gen.next(), Match: fpMatch}
		if parentId != nil {
			edges = append(edges, &MatchEdge{ParentId: *parentId, ChildId: node.Id})
		}

		// add the node to the list of nodes
		nodes = append(nodes, node)

		for key, value := range fpMatch.Values {
			// recursively call traverseMatch for each match key
			cfpNodes, cfpEdges, err := traverseMatch(&node.Id, gen, fpset, key, value)
			if err != nil {
				// Don't log this warning for now, since this is somewhat expected
				// slog.Warn(fmt.Sprintf("No such database with match key: %s", key))
				continue
			}

			// append the nodes and edges to our list
			nodes = append(nodes, cfpNodes...)
			edges = append(edges, cfpEdges...)
		}
	}

	return nodes, edges, nil
}
