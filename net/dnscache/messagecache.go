// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnscache

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/net/dns/dnsmessage"
)

// MessageCache is a cache that works at the DNS message layer,
// with its cache keyed on a DNS wire-level question, and capable
// of replying to DNS messages.
type MessageCache struct {
	// Clock is a clock, for testing. If nil, time.Now is used.
	Clock func() time.Time

	mu           sync.Mutex
	maxCacheSize int // 0 means default

	cache *lru.Cache // msgQ => *msgValue
}

func (c *MessageCache) now() time.Time {
	if c.Clock != nil {
		return c.Clock()
	}
	return time.Now()
}

// msgQ is the MessageCache cache key.
//
// It's basically a golang.org/x/net/dns/dnsmessage#Question but the
// Class is omitted (we only cache ClassINET) and we store a Go string
// instead of a 256 byte dnsmessage.Name array.
type msgQ struct {
	Name string
	Type dnsmessage.Type // A, AAAA, MX, etc
}

type msgValue struct {
	Expires time.Time
	DNSRes  string // full DNS response message, with arbitary leading two TxID bytes
}

var ErrCacheMiss = errors.New("cache miss")

var parserPool = &sync.Pool{
	New: func() interface{} { return new(dnsmessage.Parser) },
}

// ReplyFromCache writes a DNS reply to w for the provided DNS query message,
// which must begin with the two ID bytes of a DNS message.
//
// If there's a cache miss, the message is invalid or unexpected,
// ErrCacheMiss is returned. On cache hit, either nil or an error from
// a w.Write call is returned.
func (c *MessageCache) ReplyFromCache(w io.Writer, dnsQueryMessage []byte) error {
	msg := dnsQueryMessage
	p := parserPool.Get().(*dnsmessage.Parser)
	defer parserPool.Put(p)
	h, err := p.Start(dnsQueryMessage)
	if err != nil || len(msg) < 12 {
		return ErrCacheMiss // not err; caller can figure that out themselves, or not.
	}
	var (
		numQ    = binary.BigEndian.Uint16(msg[4:6])
		numAns  = binary.BigEndian.Uint16(msg[6:8])
		numAuth = binary.BigEndian.Uint16(msg[8:10])
		numAddn = binary.BigEndian.Uint16(msg[10:12])
	)
	_ = numAddn // ignore this for now; do client OSes send EDNS additional? assume so, ignore.
	if !(numQ == 1 && numAns == 0 && numAuth == 0) {
		// Something weird. We don't want to deal with it.
		return ErrCacheMiss
	}
	q, err := p.Question()
	if err != nil {
		// Already verified numQ == 1 so shouldn't happen, but:
		return ErrCacheMiss
	}
	if q.Class != dnsmessage.ClassINET {
		// We only cache the Internet class.
		return ErrCacheMiss
	}
	cacheKey := msgQ{Name: q.Name.String(), Type: q.Type}
	now := c.now()

	c.mu.Lock()
	cacheEntI, _ := c.cache.Get(cacheKey)
	cacheEnt, ok := cacheEntI.(*msgValue)
	if ok && !cacheEnt.Expires.After(now) {
		c.cache.Remove(cacheKey)
		ok = false
	}
	c.mu.Unlock()

	if !ok {
		return ErrCacheMiss
	}

	_ = h
	panic("TODO")
}
