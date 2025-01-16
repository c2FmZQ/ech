package testutil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/ech/dns"
)

func StartTestDNSServer(t *testing.T, db []dns.RR) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		body, _ := io.ReadAll(req.Body)
		qq, err := dns.DecodeMessage(body)
		if err != nil {
			t.Errorf("dns.DecodeMessage: %v", err)
			return
		}
		qq.QR = 1
		want := qq.Question[0].Name
		for i := 0; i < len(db); i++ {
			rr := db[i]
			if want != rr.Name {
				continue
			}
			if rr.Type == 5 { // CNAME
				qq.Answer = append(qq.Answer, rr)
				want = rr.Data.(string)
				i = -1
				continue
			}
			if qq.Question[0].Type == rr.Type {
				qq.Answer = append(qq.Answer, rr)
				continue
			}
		}
		t.Logf("QQ %#v", qq.Question)
		t.Logf("AA %#v", qq.Answer)
		w.Write(qq.Bytes())
	}))
}
