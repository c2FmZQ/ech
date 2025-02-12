package publish

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
)

var (
	cloudflareBaseURL = url.URL{
		Scheme: "https",
		Host:   "api.cloudflare.com",
		Path:   "/client/v4/zones",
	}

	errNotFound = errors.New("not found")
)

type StatusCode int

const (
	StatusUnknown  StatusCode = iota
	StatusUpdated             // The record was updated
	StatusNotFound            // The record was not found
	StatusNoChange            // The config list value did not change
	StatusError               // The operation resulted in a http error
)

// Target is a DNS name record to update.
type Target struct {
	Zone string
	Name string
}

// TargetResult is the result of an update.
type TargetResult struct {
	Code  StatusCode
	Error error
}

// Err converts the value to an error. It returns nil when Code is either
// [StatusUpdated] or [StatusNoChange].
func (r TargetResult) Err() error {
	switch r.Code {
	case StatusUpdated, StatusNoChange:
		return nil
	case StatusError:
		return fmt.Errorf("cloudflare error: %w", r.Error)
	default:
		return errors.New(r.String())
	}
}

func (r TargetResult) String() string {
	switch r.Code {
	case StatusUnknown:
		return "status unknown"
	case StatusUpdated:
		return "record updated"
	case StatusNotFound:
		return "not found"
	case StatusNoChange:
		return "no change"
	case StatusError:
		return fmt.Sprintf("error: %v", r.Error)
	default:
		return fmt.Sprintf("invalid status code: %d", r.Code)
	}
}

// ECHPublisher is the interface for publishing ECH Config Lists to DNS.
type ECHPublisher interface {
	// PublishECH updates the target DNS records with a new config list.
	PublishECH(ctx context.Context, records []Target, configList []byte) []TargetResult
}

// NewCloudflarePublisher returns a new CloudflarePublisher. The API token must
// have the DNS:Read and DNS:Edit permissions on the target zone(s).
func NewCloudflarePublisher(apiToken string) *CloudflarePublisher {
	cf := &CloudflarePublisher{
		baseURL:  cloudflareBaseURL,
		client:   retryablehttp.NewClient(),
		zoneIDs:  make(map[string]string),
		apiToken: apiToken,
	}
	cf.client.Logger = nil
	return cf
}

var _ ECHPublisher = (*CloudflarePublisher)(nil)

// CloudflarePublisher publishes ECH Config Lists to DNS using the cloudflare
// API.
type CloudflarePublisher struct {
	baseURL  url.URL
	client   *retryablehttp.Client
	zoneIDs  map[string]string
	apiToken string
}

type zoneName struct {
	Zone string
	Name string
}

type idData struct {
	ZoneID   string
	RecordID string
	Data     httpsData
}

type httpsData struct {
	Priority int    `json:"priority"`
	Target   string `json:"target"`
	Value    string `json:"value"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e cfError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

type cfErrors []cfError

func (e cfErrors) Error() string {
	errs := make([]error, 0, len(e))
	for _, ee := range e {
		errs = append(errs, ee)
	}
	return errors.Join(errs...).Error()
}

// PublishECH updates the target DNS records with a new config list.
func (cf *CloudflarePublisher) PublishECH(ctx context.Context, records []Target, configList []byte) []TargetResult {
	zones := make(map[string]bool)
	data := make(map[zoneName]idData)

	newValue := base64.StdEncoding.EncodeToString(configList)
	results := make([]TargetResult, 0, len(records))

	for _, r := range records {
		var result TargetResult
		if !zones[r.Zone] {
			zones[r.Zone] = true
			if err := cf.getZoneData(ctx, r.Zone, data); err != nil {
				if err == errNotFound {
					result.Code = StatusNotFound
				} else {
					result.Code = StatusError
					result.Error = err
				}
				results = append(results, result)
				continue
			}
		}

		v, exists := data[zoneName{r.Zone, r.Name}]
		if !exists {
			result.Code = StatusNotFound
			results = append(results, result)
			continue
		}
		params := strings.Split(v.Data.Value, " ")
		var newParams []string
		var oldValue string
		for _, p := range params {
			if k, v, ok := strings.Cut(p, "="); ok && k == "ech" {
				oldValue = strings.Trim(v, `"`)
				continue
			}
			newParams = append(newParams, p)
		}
		if newValue == oldValue {
			result.Code = StatusNoChange
			results = append(results, result)
			continue
		}
		newParams = append(newParams, fmt.Sprintf(`ech="%s"`, newValue))
		v.Data.Value = strings.Join(newParams, " ")

		if err := cf.updateRecord(ctx, v.ZoneID, v.RecordID, v.Data); err != nil {
			result.Code = StatusError
			result.Error = err
			results = append(results, result)
			continue
		}
		result.Code = StatusUpdated
		results = append(results, result)
	}
	return results
}

func (cf *CloudflarePublisher) getZoneData(ctx context.Context, zone string, data map[zoneName]idData) error {
	zoneID, exists := cf.zoneIDs[zone]
	if !exists {
		u := cf.baseURL
		q := u.Query()
		q.Set("name", zone)
		u.RawQuery = q.Encode()
		req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cf.apiToken)
		resp, err := cf.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("status code %d", resp.StatusCode)
		}

		b, _ := io.ReadAll(resp.Body)
		var result struct {
			Success bool     `json:"success"`
			Errors  cfErrors `json:"errors"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := json.Unmarshal(b, &result); err != nil {
			return err
		}
		if !result.Success || len(result.Errors) > 0 {
			return result.Errors
		}
		if len(result.Result) > 0 {
			zoneID = result.Result[0].ID
		}
		cf.zoneIDs[zone] = zoneID
	}
	if zoneID == "" {
		return errNotFound
	}

	for page := 1; ; page++ {
		u := cf.baseURL
		u.Path += "/" + zoneID + "/dns_records"
		q := u.Query()
		q.Set("type", "HTTPS")
		q.Set("per_page", "20")
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()
		req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cf.apiToken)
		resp, err := cf.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("status code %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		var result struct {
			Success bool     `json:"success"`
			Errors  cfErrors `json:"errors"`
			Result  []struct {
				ID   string    `json:"id"`
				Name string    `json:"name"`
				Data httpsData `json:"data"`
			} `json:"result"`
			ResultInfo struct {
				Count      int `json:"count"`
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		if err := json.Unmarshal(b, &result); err != nil {
			return err
		}
		if !result.Success {
			return result.Errors
		}
		for _, r := range result.Result {
			data[zoneName{zone, r.Name}] = idData{zoneID, r.ID, r.Data}
		}
		if len(result.Result) == 0 || result.ResultInfo.Page >= result.ResultInfo.TotalPages || result.ResultInfo.Page*result.ResultInfo.PerPage >= result.ResultInfo.Count {
			break
		}
	}
	return nil
}

func (cf *CloudflarePublisher) updateRecord(ctx context.Context, zoneID, recordID string, data httpsData) error {
	b, err := json.Marshal(struct {
		Data httpsData `json:"data"`
	}{Data: data})
	if err != nil {
		return err
	}
	u := cf.baseURL
	u.Path += "/" + zoneID + "/dns_records/" + recordID
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPatch, u.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cf.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cf.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}

	b, _ = io.ReadAll(resp.Body)
	var result struct {
		Success bool     `json:"success"`
		Errors  cfErrors `json:"errors"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return err
	}
	if !result.Success {
		return result.Errors
	}
	return nil
}
