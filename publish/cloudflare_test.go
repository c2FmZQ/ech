package publish

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
)

type cfResponse struct {
	Result     any          `json:"result,omitzero"`
	ResultInfo cfResultInfo `json:"result_info,omitzero"`
	Success    bool         `json:"success"`
	Errors     []any        `json:"errors"`
	Messages   []any        `json:"messages"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

type cfZone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	records []*cfRecord
}

type cfRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
	Data any    `json:"data"`
}

type cfHTTPS struct {
	Priority int    `json:"priority"`
	Target   string `json:"target"`
	Value    string `json:"value"`
}

func TestCloudflare(t *testing.T) {
	zones := []*cfZone{
		{
			ID:   "zone1",
			Name: "example.org",
			records: []*cfRecord{
				{
					ID:   "record1",
					Name: "example.org",
					Type: "HTTPS",
					TTL:  1,
					Data: cfHTTPS{Priority: 1, Target: ".", Value: "alpn=\"h3\" ech=\"AQID\""},
				},
				{
					ID:   "record2",
					Name: "*.example.org",
					Type: "HTTPS",
					TTL:  1,
					Data: cfHTTPS{Priority: 1, Target: ".", Value: "alpn=\"h2\""},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		body := func() []byte {
			defer req.Body.Close()
			b, err := io.ReadAll(req.Body)
			if err != nil {
				t.Errorf("body: %v", err)
				return nil
			}
			return b
		}
		p := req.URL.Path
		switch {
		case req.Method == "GET" && p == "/client/v4/zones":
			name := req.Form.Get("name")
			resp := cfResponse{
				Success: true,
				ResultInfo: cfResultInfo{
					Page:       1,
					PerPage:    20,
					TotalPages: 1,
				},
			}
			z := []*cfZone{}
			for _, zz := range zones {
				if name == zz.Name || name == "" {
					z = append(z, zz)
				}
			}
			resp.Result = z
			resp.ResultInfo.Count = len(z)
			resp.ResultInfo.TotalCount = len(z)
			v, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("json: %v", err)
			}
			w.Write(v)

		case req.Method == "GET" && strings.HasPrefix(p, "/client/v4/zones/") && strings.HasSuffix(p, "/dns_records"):
			typ := req.Form.Get("type")
			zone := strings.Split(p, "/")[4]
			resp := cfResponse{
				Success: true,
				ResultInfo: cfResultInfo{
					Page:       1,
					PerPage:    20,
					TotalPages: 1,
				},
			}
			r := []*cfRecord{}
			for _, zz := range zones {
				if zz.ID != zone {
					continue
				}
				for _, rr := range zz.records {
					if rr.Type == typ || typ == "" {
						r = append(r, rr)
					}
				}
			}
			resp.Result = r
			resp.ResultInfo.Count = len(r)
			resp.ResultInfo.TotalCount = len(r)

			v, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("json: %v", err)
			}
			w.Write(v)

		case req.Method == "PATCH" && strings.HasPrefix(p, "/client/v4/zones/") && strings.Index(p, "/dns_records/") > 0:
			parts := strings.Split(p, "/")
			zone := parts[4]
			record := parts[6]

			for _, zz := range zones {
				if zz.ID != zone {
					continue
				}
				for _, rr := range zz.records {
					if rr.ID != record {
						continue
					}
					if err := json.Unmarshal(body(), &rr); err != nil {
						t.Errorf("json: %v", err)
					}
					fmt.Fprintln(w, `{"success": true}`)
					return
				}
			}
			fmt.Fprintln(w, `{"success": false}`)

		default:
			t.Errorf("Received %s request for %q", req.Method, p)
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("ts.URL: %v", err)
	}
	u.Path = "/client/v4/zones"

	cf := &CloudflarePublisher{
		baseURL: *u,
		client:  retryablehttp.NewClient(),
		zoneIDs: make(map[string]string),
	}

	targets := []Target{
		{Zone: "foo.org", Name: "foo.org"},
		{Zone: "example.org", Name: "example.org"},
		{Zone: "example.org", Name: "*.example.org"},
		{Zone: "example.org", Name: "foo.example.org"},
	}

	t.Run("FirstUpdate", func(t *testing.T) {
		got := cf.PublishECH(t.Context(), targets, []byte{1, 2, 3})
		want := []TargetResult{
			{Code: StatusNotFound},
			{Code: StatusNoChange},
			{Code: StatusUpdated},
			{Code: StatusNotFound},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("results = %#v, want %#v", got, want)
		}
	})

	t.Run("SecondUpdate", func(t *testing.T) {
		got := cf.PublishECH(t.Context(), targets, []byte{1, 2, 3})
		want := []TargetResult{
			{Code: StatusNotFound},
			{Code: StatusNoChange},
			{Code: StatusNoChange},
			{Code: StatusNotFound},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("results = %#v, want %#v", got, want)
		}
	})
}
