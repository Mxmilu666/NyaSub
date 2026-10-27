package httpapi

import (
	"encoding/base64"
	"errors"
	"sort"
	"strings"

	"nyasub/internal/mihomo"
	"nyasub/internal/sharelink"
	"nyasub/internal/store"
)

var errNoXrayNodes = errors.New("profile has no nodes compatible with Xray share links")

// buildXraySubscription renders selected original nodes as a standard
// base64-encoded V2Ray/Xray share-link subscription. Mihomo chains cannot be
// represented by share links, so only profile nodes are included; chain-only
// behavior remains available in the Mihomo YAML subscription.
func buildXraySubscription(bundle *profileBundle, result *mihomo.Result) ([]byte, error) {
	nodes := append([]store.Node(nil), bundle.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool {
		left, right := result.NodeNames[nodes[i].ID], result.NodeNames[nodes[j].ID]
		if left != right {
			return left < right
		}
		return nodes[i].ID < nodes[j].ID
	})
	links := make([]string, 0, len(nodes))
	for _, stored := range nodes {
		node, err := nodeToMihomo(stored)
		if err != nil {
			return nil, err
		}
		if name := result.NodeNames[stored.ID]; name != "" {
			node.Name = name
		}
		link, err := sharelink.Build(node)
		if errors.Is(err, sharelink.ErrUnsupportedProtocol) {
			continue
		}
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return nil, errNoXrayNodes
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))), nil
}
