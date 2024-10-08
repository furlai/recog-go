package recog

import (
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

func TraverseMatch(fpset *FingerprintSet, dbtype string, text string) ([]*MatchNode, []*MatchEdge, error) {
	return traverseMatch(nil, fpset, dbtype, text)
}

// Recursively match against the fingerprint database.
func traverseMatch(parentId *uuid.UUID, fpset *FingerprintSet, dbtype string, text string) ([]*MatchNode, []*MatchEdge, error) {
	var nodes []*MatchNode
	var edges []*MatchEdge

	// no matches? return nil now
	fps, err := fpset.MatchAll(dbtype, text)
	if err != nil {
		return nil, nil, err
	}

	// iterate over the matches and construct the graph from the results
	for _, fpMatch := range fps {
		node := &MatchNode{Id: uuid.New(), Match: fpMatch}
		if parentId != nil {
			edges = append(edges, &MatchEdge{ParentId: *parentId, ChildId: node.Id})
		}

		// add the node to the list of nodes
		nodes = append(nodes, node)

		for key, value := range fpMatch.Values {
			// recursively call traverseMatch for each match key
			cfpNodes, cfpEdges, err := traverseMatch(&node.Id, fpset, key, value)
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
