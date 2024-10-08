package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/xlab/treeprint"

	"github.com/google/uuid"

	flags "github.com/jessevdk/go-flags"

	"github.com/runZeroInc/recog-go"
)

type Options struct {
	Root                    string `long:"root" description:"Root directory of the fingerprint files" default:"xml"`
	File                    string `long:"file" short:"f" description:"File containing the stream of input data, or - for stdin" default:"-"`
	Headers                 bool   `long:"csv-headers" short:"c" description:"File contains CSV headers"`
	HeaderMatchKey          string `long:"header-match-key" short:"k" description:"Header name to use as match key (only relevant if -c is used)" default:"key"`
	HeaderValue             string `long:"header-value" short:"v" description:"Header name to use as match value (only relevant if -c is used)" default:"value"`
	Matches                 string `long:"matches" short:"m" description:"Match key to use for all input data" default:"key"`
	Performance             bool   `long:"performance" short:"p" description:"Enable performance profiling"`
	PerformanceExtendedInfo bool   `long:"performance-extended" short:"e" description:"Enable software information in performance profiling"`
	Nomatch                 bool   `long:"nomatch" short:"n" description:"Print only non-matching input"`
}

// Renders / prints a hierarchical tree of the matches.
// The root level contains the root nodes that do not have a parent. If a node is a parent, it is added as a branch
// and its children are added under it.
func printTree(rootText string, nodes []*recog.MatchNode, edges []*recog.MatchEdge) {
	tree := treeprint.NewWithRoot(rootText)
	nodeMap := make(map[uuid.UUID]treeprint.Tree)
	matchNodeMap := make(map[uuid.UUID]*recog.MatchNode)

	// create a map of all matchnodes by id
	for _, node := range nodes {
		matchNodeMap[node.Id] = node
	}

	// get a map of any child node ids
	childMap := make(map[uuid.UUID]bool)
	for _, edge := range edges {
		childMap[edge.ChildId] = true
	}

	// add root nodes
	for _, node := range nodes {
		// only add the root node if it has no parent
		if _, ok := childMap[node.Id]; !ok {
			nodeMap[node.Id] = tree.AddMetaBranch(node.Match.Fingerprint.DB.Name, node.Match.Fingerprint.Description.Text)
		}
	}

	// add child nodes to the tree
	for _, edge := range edges {
		if parent, ok := nodeMap[edge.ParentId]; ok {
			nodeMap[edge.ChildId] = parent.AddMetaBranch(matchNodeMap[edge.ChildId].Match.Fingerprint.DB.Name, matchNodeMap[edge.ChildId].Match.Fingerprint.Description.Text)
		}
	}

	fmt.Println(tree.String())
}

func printValues(values map[string]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		// skip matched key
		if key == "matched" {
			continue
		}
		keys = append(keys, key)
	}

	// sort keys for consistent output, considering the dot segments within
	// key names first, then their alphanumeric order. Group by number of segments before sort. For example:
	// a.b < a.b.c
	sort.Slice(keys, func(i, j int) bool {
		// split keys into segments
		ki := strings.Split(keys[i], ".")
		kj := strings.Split(keys[j], ".")

		if len(ki) < len(kj) {
			return true
		}

		if len(ki) > len(kj) {
			return false
		}

		// compare segments
		for k := 0; k < len(ki); k++ {
			if ki[k] < kj[k] {
				return true
			}
			if ki[k] > kj[k] {
				return false
			}
		}

		return false
	})

	// print the match values in sorted order
	for _, key := range keys {
		fmt.Printf("    %s: %s\n", key, values[key])
	}
}

func printNodes(nodes []*recog.MatchNode) {
	for _, node := range nodes {
		// print a nicely formatted plaintext output of each match
		description := "Unknown"
		if node.Match.Fingerprint.Description != nil {
			description = node.Match.Fingerprint.Description.Text
		}
		fmt.Printf("Matched: %s\n", description)
		fmt.Printf("  Id: %s\n", node.Id)
		fmt.Printf("  Type: %s\n", node.Match.Fingerprint.DB.DatabaseType)
		fmt.Printf("  Values:\n")

		printValues(node.Match.Values)
		fmt.Println()
	}
}

func truncateText(text string, length int) string {
	if len(text) > length {
		return text[:length] + "..."
	}
	return text
}

func MustParseFloat(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	var opts Options
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		panic(err)
	}

	// load fingerprint databases
	fpset, err := recog.LoadFingerprintsDir(opts.Root)
	if err != nil {
		fmt.Printf("Failed to load fingerprints: %s", err)
		os.Exit(1)
	}

	// read input from args or stdin
	var scanner *csv.Reader
	if opts.File == "-" {
		scanner = csv.NewReader(os.Stdin)
	} else {
		// opts.File is a line separated list of strings
		file, err := os.Open(opts.File)
		if err != nil {
			fmt.Printf("Failed to open file: %s", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner = csv.NewReader(file)
	}

	// parse headers
	var headers []string
	if opts.Headers {
		headers, err = scanner.Read()
		if err != nil {
			fmt.Printf("Failed to read headers: %s", err)
			os.Exit(1)
		}
	}

	// find the source and proof index from the header set
	sourceIndex := -1
	proofIndex := 0
	for i, header := range headers {
		if header == opts.HeaderMatchKey {
			sourceIndex = i
		}
		if header == opts.HeaderValue {
			proofIndex = i
		}
	}

	if opts.Performance {
		fmt.Println("Performance profiling mode")

		// start performance profiling
		total := 0
		matched := 0
		package_counts := make(map[string]int)
		software_counts := make(map[string]int)

		// iterate over the csv records
		for {
			record, err := scanner.Read()
			if err != nil {
				break
			}

			// find the match key from the source header if CSV
			matches := opts.Matches
			if sourceIndex != -1 {
				matches = record[sourceIndex]
			}

			nodes, _, err := recog.TraverseMatch(fpset, matches, record[proofIndex])
			if err != nil {
				fmt.Printf("Matching failed: %s", err)
				os.Exit(1)
			}

			if opts.PerformanceExtendedInfo {
				for _, node := range nodes {
					if v, ok := node.Match.Values["software.package.name"]; ok {
						package_counts[v]++
					}

					if v, ok := node.Match.Values["software.product"]; ok {
						software_counts[v]++
					}
				}
			}

			total++

			if len(nodes) > 0 {
				matched++
			}
		}

		fmt.Printf("Performance profiling results (NOTE: showing all regardless of certainty) total=%d matched=%d\n", total, matched)
		if opts.PerformanceExtendedInfo {
			// make a list of keys that represent the package counts ordered descending
			package_keys := make([]string, 0, len(package_counts))
			for k := range package_counts {
				package_keys = append(package_keys, k)
			}

			sort.Slice(package_keys, func(i, j int) bool {
				return package_counts[package_keys[i]] > package_counts[package_keys[j]]
			})

			// make a list of keys that represent the software counts ordered descending
			software_keys := make([]string, 0, len(software_counts))
			for k := range software_counts {
				software_keys = append(software_keys, k)
			}

			sort.Slice(software_keys, func(i, j int) bool {
				return software_counts[software_keys[i]] > software_counts[software_keys[j]]
			})

			// print the packages and software as bulleted lists
			fmt.Println("****** Package Counts ******")
			for v := range package_keys {
				fmt.Printf("    %s: %d\n", package_keys[v], package_counts[package_keys[v]])
			}

			fmt.Println("****** Software Counts ******")
			for v := range software_keys {
				fmt.Printf("    %s: %d\n", software_keys[v], software_counts[software_keys[v]])
			}
		}
		os.Exit(0)
	}

	// match the input text against the fingerprints (recursive)
	for {
		record, err := scanner.Read()
		if err != nil {
			break
		}

		// find the match key from the source header
		matches := opts.Matches
		if sourceIndex != -1 {
			matches = record[sourceIndex]
		}

		nodes, edges, err := recog.TraverseMatch(fpset, matches, record[proofIndex])
		if err != nil {
			fmt.Printf("Matching failed: %s", err)
			os.Exit(1)
		}

		// if no matches, print the input text and continue
		if opts.Nomatch {
			if len(nodes) == 0 {
				fmt.Printf("NO MATCH: %s\n", record[proofIndex])
			}
			continue
		}

		// group matches by type, select the best type based on the certainty, and track the rejected matches
		// for later analysis
		bestMatches := make(map[string]*recog.MatchNode)
		rejects := make([]*recog.MatchNode, 0)
		for _, node := range nodes {
			if bestMatch, ok := bestMatches[node.Match.Fingerprint.DB.DatabaseType]; ok {
				// TODO: Direct == comparison of float values is not safe, may cause flapping.
				if MustParseFloat(node.Match.Values["fp.certainty"]) > MustParseFloat(bestMatch.Match.Values["fp.certainty"]) {
					bestMatches[node.Match.Fingerprint.DB.DatabaseType] = node
					rejects = append(rejects, bestMatch)
				} else {
					rejects = append(rejects, node)
				}
			} else {
				bestMatches[node.Match.Fingerprint.DB.DatabaseType] = node
			}
		}

		// print the best matches
		fmt.Println("****** Best Matches ******")
		v := make([]*recog.MatchNode, 0, len(bestMatches))
		for _, match := range bestMatches {
			v = append(v, match)
		}
		printNodes(v)

		// print the rejected matches
		if len(rejects) > 0 {
			fmt.Println("****** Rejected Matches ******")
			printNodes(rejects)
		}

		fmt.Println("****** Tree ******")
		printTree(fmt.Sprintf("Input: %s", truncateText(record[proofIndex], 70)), nodes, edges)
	}
}
