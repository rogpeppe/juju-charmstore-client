// Copyright 2017 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package iomon_test

import (
	"bytes"
	"strings"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/charmstore-client/internal/iomon"
)

type iomonSuite struct{}

var _ = gc.Suite(&iomonSuite{})

func (*iomonSuite) TestMonitor(c *gc.C) {
	setterCh := make(statusSetter)
	t0 := time.Now()
	clock := testing.NewClock(t0)
	m := iomon.New(iomon.Params{
		Size:           1000,
		Setter:         setterCh,
		UpdateInterval: time.Second,
		Clock:          clock,
	})
	c.Assert(setterCh.wait(c), jc.DeepEquals, iomon.Status{
		Current: 0,
		Total:   1000,
	})
	clock.Advance(time.Second)
	// Nothing changed, so no status should be sent.
	setterCh.expectNothing(c)
	// Calling update should not trigger a status send.
	m.Update(500)
	setterCh.expectNothing(c)
	clock.Advance(time.Second)
	c.Assert(setterCh.wait(c), jc.DeepEquals, iomon.Status{
		Current: 500,
		Total:   1000,
	})
	// Updating to the same value should not trigger a status send.
	m.Update(500)
	clock.Advance(time.Second)
	setterCh.expectNothing(c)

	m.Update(700)
	m.Kill()
	// One last status update should be sent when it's killed.
	c.Assert(setterCh.wait(c), jc.DeepEquals, iomon.Status{
		Current: 700,
		Total:   1000,
	})
	m.Wait()
	clock.Advance(10 * time.Second)
	setterCh.expectNothing(c)
}

var formatByteCountTests = []struct {
	n      int64
	expect string
}{
	{0, "0KiB"},
	{2567, "3KiB"},
	{9876 * 1024, "9876KiB"},
	{10 * 1024 * 1024, "10.0MiB"},
	{20 * 1024 * 1024 * 1024, "20.0GiB"},
	{55068359375, "51.3GiB"},
}

func (*iomonSuite) TestFormatByteCount(c *gc.C) {
	for i, test := range formatByteCountTests {
		c.Logf("test %d: %v", i, test.n)
		c.Assert(iomon.FormatByteCount(test.n), gc.Equals, test.expect)
	}
}

var statusStringTests = []struct {
	about  string
	status iomon.Status
	expect string
}{{
	about:  "all zero",
	expect: "100%      0KiB",
}, {
	about: "small data",
	status: iomon.Status{
		Total: 7,
	},
	expect: "  0%      0KiB",
}, {
	about: "large data",
	status: iomon.Status{
		Current: 1 << 61,
		Total:   1 << 62,
	},
	expect: " 50% 2147483648.0GiB",
}}

func (*iomonSuite) TestStatusString(c *gc.C) {
	for i, test := range statusStringTests {
		c.Logf("test %d: %v", i, test.about)
		c.Assert(test.status.String(), gc.Equals, test.expect)
	}
}

// Note: newlines in this are treated as carriage-returns
// when comparing and trailing dollars are removed.
var printerText = `
something                                       0%      0KiB$
something                                       0%      0KiB$
something                                       0%      0KiB$
something                                       0%      1KiB$
something                                       0%     10KiB$
something                                       0%     98KiB$
something                                       0%    977KiB$
something                                       0%   9766KiB$
something                                       0%   95.4MiB$
something                                       0%  953.7MiB$
something                                       0% 9536.7MiB$
something                                       0%   93.1GiB$
something                                       0%  931.3GiB$
something                                       0% 9313.2GiB$
something                                       1% 93132.3GiB$
something                                      10% 931322.6GiB$
something                                     100% 9313225.7GiB$
something                                       0%      0KiB   $
                                                             $
`

func (*iomonSuite) TestPrinter(c *gc.C) {
	var buf bytes.Buffer
	p := iomon.NewPrinter(&buf, "something")
	const total = 1e16
	for i := int64(1); i <= total; i *= 10 {
		p.SetStatus(iomon.Status{
			Current: i,
			Total:   total,
		})
	}
	p.SetStatus(iomon.Status{
		Current: 0,
		Total:   total,
	})
	p.Clear()
	got := strings.Replace(buf.String(), "\r", "\n", -1)
	want := strings.Replace(printerText, "$\n", "\n", -1)
	c.Assert(got, gc.Equals, want)
}

type statusSetter chan iomon.Status

func (ch statusSetter) wait(c *gc.C) iomon.Status {
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		c.Fatalf("timed out waiting for status")
		panic("unreachable")
	}
}

func (ch statusSetter) expectNothing(c *gc.C) {
	select {
	case s := <-ch:
		c.Fatalf("unexpected status received %#v", s)
	case <-time.After(10 * time.Millisecond):
	}
}

func (ch statusSetter) SetStatus(s iomon.Status) {
	ch <- s
}
