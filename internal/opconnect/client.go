package opconnect

import (
	"context"
	"fmt"
	"sort"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// Client wraps the 1Password SDK using service account authentication.
type Client struct {
	sdk *onepassword.Client
	ctx context.Context
}

// Item represents a 1Password item.
type Item struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Vault   Vault   `json:"vault"`
	Fields  []Field `json:"fields"`
	Version int     `json:"version"`
}

// Vault represents a 1Password vault reference.
type Vault struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Field represents a field in a 1Password item.
type Field struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

// New creates a new 1Password SDK client authenticated with a service account token.
func New(ctx context.Context, token string) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	sdk, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("Secret Gate", "1.1.0"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating 1Password SDK client: %w", err)
	}

	return &Client{sdk: sdk, ctx: ctx}, nil
}

// GetVaults returns all vaults accessible to the service account.
func (c *Client) GetVaults() ([]Vault, error) {
	overviews, err := c.sdk.Vaults().List(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	vaults := make([]Vault, 0, len(overviews))
	for _, v := range overviews {
		vaults = append(vaults, Vault{ID: v.ID, Name: v.Title})
	}
	return vaults, nil
}

// GetItemByTitle fetches an item by vault ID and item title.
func (c *Client) GetItemByTitle(vaultID, itemTitle string) (*Item, error) {
	items, err := c.sdk.Items().List(c.ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing items: %w", err)
	}

	for _, item := range items {
		if item.Title == itemTitle {
			return c.GetItem(vaultID, item.ID)
		}
	}

	return nil, fmt.Errorf("item not found: %s", itemTitle)
}

// GetItem fetches a full item by vault ID and item ID.
func (c *Client) GetItem(vaultID, itemID string) (*Item, error) {
	item, err := c.sdk.Items().Get(c.ctx, vaultID, itemID)
	if err != nil {
		return nil, fmt.Errorf("getting item: %w", err)
	}

	converted := convertSDKItem(item)
	return &converted, nil
}

// GetSecret retrieves a secret item and returns it as a map of field labels to values.
func (c *Client) GetSecret(vaultName, itemTitle string) (map[string]string, error) {
	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	var vaultID string
	for _, v := range vaults {
		if v.Name == vaultName || v.ID == vaultName {
			vaultID = v.ID
			break
		}
	}

	if vaultID == "" {
		return nil, fmt.Errorf("vault not found: %s", vaultName)
	}

	item, err := c.GetItemByTitle(vaultID, itemTitle)
	if err != nil {
		return nil, fmt.Errorf("getting item: %w", err)
	}

	fields := make(map[string]string)
	for _, f := range item.Fields {
		if f.Label != "" {
			fields[f.Label] = f.Value
		}
	}

	return fields, nil
}

// HealthCheck verifies that the SDK can authenticate and access 1Password.
func (c *Client) HealthCheck() error {
	_, err := c.sdk.Vaults().List(c.ctx)
	if err != nil {
		return fmt.Errorf("1Password SDK health check failed: %w", err)
	}
	return nil
}

// SearchResult represents a fuzzy search match.
type SearchResult struct {
	Item      Item    `json:"item"`
	VaultName string  `json:"vault_name"`
	VaultID   string  `json:"vault_id"`
	Score     float64 `json:"score"`
	MatchType string  `json:"match_type"` // "exact", "prefix", "contains", "fuzzy"
}

// FieldInfo holds metadata about a field without its value.
type FieldInfo struct {
	Label string `json:"label"`
	Type  string `json:"type"`
}

// GetItemFields returns field metadata for an item without values.
func (c *Client) GetItemFields(vaultName, itemTitle string) ([]FieldInfo, string, string, error) {
	var item *Item
	var actualVault, actualTitle string

	if vaultName == "" || vaultName == "_auto_" {
		results, err := c.SearchSecrets(itemTitle, 5)
		if err != nil {
			return nil, "", "", fmt.Errorf("searching secrets: %w", err)
		}
		if len(results) == 0 {
			return nil, "", "", fmt.Errorf("item not found: %s", itemTitle)
		}
		best := results[0]
		if best.MatchType != "exact" && best.MatchType != "prefix" && best.Score < 0.8 {
			var suggestions []string
			for _, r := range results {
				suggestions = append(suggestions, r.Item.Title)
			}
			return nil, "", "", fmt.Errorf("no exact match for '%s'. Did you mean: %s", itemTitle, strings.Join(suggestions, ", "))
		}
		item, err = c.GetItem(best.VaultID, best.Item.ID)
		if err != nil {
			return nil, "", "", fmt.Errorf("getting item: %w", err)
		}
		actualVault = best.VaultName
		actualTitle = best.Item.Title
	} else {
		vaults, err := c.GetVaults()
		if err != nil {
			return nil, "", "", fmt.Errorf("listing vaults: %w", err)
		}
		var vaultID string
		for _, v := range vaults {
			if v.Name == vaultName || v.ID == vaultName {
				vaultID = v.ID
				actualVault = v.Name
				break
			}
		}
		if vaultID == "" {
			return nil, "", "", fmt.Errorf("vault not found: %s", vaultName)
		}
		item, err = c.GetItemByTitle(vaultID, itemTitle)
		if err != nil {
			return nil, "", "", fmt.Errorf("getting item: %w", err)
		}
		actualTitle = item.Title
	}

	var fields []FieldInfo
	for _, f := range item.Fields {
		if f.Label != "" {
			fields = append(fields, FieldInfo{Label: f.Label, Type: f.Type})
		}
	}

	return fields, actualVault, actualTitle, nil
}

// ListItemsInVault returns all items in a vault (titles only, no fields).
func (c *Client) ListItemsInVault(vaultID string) ([]Item, error) {
	overviews, err := c.sdk.Items().List(c.ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing items: %w", err)
	}

	items := make([]Item, 0, len(overviews))
	for _, item := range overviews {
		items = append(items, Item{
			ID:    item.ID,
			Title: item.Title,
			Vault: Vault{ID: item.VaultID},
		})
	}
	return items, nil
}

// SearchSecrets searches for secrets across all vaults using fuzzy matching.
func (c *Client) SearchSecrets(query string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 10
	}

	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	var results []SearchResult
	queryLower := strings.ToLower(query)

	for _, vault := range vaults {
		items, err := c.ListItemsInVault(vault.ID)
		if err != nil {
			// Preserve the existing behavior: skip vaults the service account cannot access.
			continue
		}

		for _, item := range items {
			titleLower := strings.ToLower(item.Title)
			score, matchType := fuzzyScore(queryLower, titleLower)

			if score > 0 {
				results = append(results, SearchResult{
					Item:      item,
					VaultName: vault.Name,
					VaultID:   vault.ID,
					Score:     score,
					MatchType: matchType,
				})
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// FindSecretAcrossVaults finds a secret by name across all vaults.
func (c *Client) FindSecretAcrossVaults(secretName string) (map[string]string, string, string, error) {
	results, err := c.SearchSecrets(secretName, 5)
	if err != nil {
		return nil, "", "", fmt.Errorf("searching secrets: %w", err)
	}

	if len(results) == 0 {
		return nil, "", "", fmt.Errorf("secret not found: %s", secretName)
	}

	best := results[0]
	if best.MatchType != "exact" && best.MatchType != "prefix" && best.Score < 0.8 {
		var suggestions []string
		for _, r := range results {
			suggestions = append(suggestions, r.Item.Title)
		}
		return nil, "", "", fmt.Errorf("no exact match for '%s'. Did you mean: %s", secretName, strings.Join(suggestions, ", "))
	}

	item, err := c.GetItem(best.VaultID, best.Item.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("getting item: %w", err)
	}

	fields := make(map[string]string)
	for _, f := range item.Fields {
		if f.Label != "" {
			fields[f.Label] = f.Value
		}
	}

	return fields, best.VaultName, best.Item.Title, nil
}

func convertSDKItem(item onepassword.Item) Item {
	fields := make([]Field, 0, len(item.Fields))
	for _, field := range item.Fields {
		fields = append(fields, Field{
			ID:    field.ID,
			Type:  string(field.FieldType),
			Label: field.Title,
			Value: field.Value,
		})
	}

	return Item{
		ID:      item.ID,
		Title:   item.Title,
		Vault:   Vault{ID: item.VaultID},
		Fields:  fields,
		Version: int(item.Version),
	}
}

// fuzzyScore calculates a match score between query and target.
// Returns score (0-1) and match type.
func fuzzyScore(query, target string) (float64, string) {
	if query == target {
		return 1.0, "exact"
	}

	if strings.HasPrefix(target, query) {
		return 0.9, "prefix"
	}

	if strings.Contains(target, query) {
		idx := strings.Index(target, query)
		posScore := 1.0 - float64(idx)/float64(len(target))
		lenScore := float64(len(query)) / float64(len(target))
		return 0.7 * (posScore*0.5 + lenScore*0.5), "contains"
	}

	qi := 0
	matches := 0
	for ti := 0; ti < len(target) && qi < len(query); ti++ {
		if target[ti] == query[qi] {
			matches++
			qi++
		}
	}

	if qi == len(query) {
		score := float64(matches) / float64(max(len(query), len(target)))
		return score * 0.5, "fuzzy"
	}

	queryWords := strings.FieldsFunc(query, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	targetWords := strings.FieldsFunc(target, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})

	wordMatches := 0
	for _, qw := range queryWords {
		for _, tw := range targetWords {
			if strings.Contains(tw, qw) || strings.Contains(qw, tw) {
				wordMatches++
				break
			}
		}
	}

	if wordMatches > 0 {
		score := float64(wordMatches) / float64(len(queryWords))
		return score * 0.4, "fuzzy"
	}

	return 0, ""
}
