// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdial

import (
	"context"
	"encoding/hex"
	"flag"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var dohBase = flag.String("doh-base", "", "DoH base URL for manual DoH tests; e.g. \"http://100.68.82.120:47830/dns-query\"")

func TestDoHResolve(t *testing.T) {
	if *dohBase == "" {
		t.Skip("skipping manual test without --doh-base= set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var r net.Resolver
	r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &dohConn{ctx: ctx, baseURL: *dohBase}, nil
	}
	addrs, err := r.LookupIP(ctx, "ip4", "danga.com.")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %q", addrs)
}

func TestDNSResponseParse(t *testing.T) {
	const hexRes = `3cfb818000010004000000000564616e676103636f6d00000100010564616e676103636f6d000001000100000e050004d8ef22150564616e676103636f6d000001000100000e050004d8ef20150564616e676103636f6d000001000100000e050004d8ef24150564616e676103636f6d000001000100000e050004d8ef2615`
	pkt, err := hex.DecodeString(hexRes)
	if err != nil {
		t.Fatal(err)
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(pkt); err != nil {
		t.Fatal(err)
	}
	q, err := parser.Question()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Q: %+v", q)
	if _, err := parser.Question(); err != dnsmessage.ErrSectionDone {
		t.Fatalf("expected exactly 1 question; reading 2nd: %v", err)
	}
	for {
		rh, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		res, err := parser.UnknownResource()
		if err != nil {
			t.Fatalf("UnknownResource: %v", err)
		}
		t.Logf("RR: %+v = type %v, %q", rh, res.Type, res.Data)
	}
	auths, err := parser.AllAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	addls, err := parser.AllAdditionals()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Authorities = %v, Additionals = %v", len(auths), len(addls))

}
