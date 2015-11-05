package openvpn

import (
	"github.com/levenlabs/go-openvpn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"strings"
	. "testing"
	"time"
)

func Test(t *T) {
	f := `OpenVPN CLIENT LIST
Updated,Thu Nov  5 15:34:43 2015
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
test1,6.6.6.6:1000,100,98,Thu Nov  5 15:34:43 2015
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.0.0.1,test1,6.6.6.6:1000,Thu Nov  5 15:34:43 2015
10.1.0.1C,test1,6.6.6.6:1000,Thu Nov  5 15:34:43 2015
10.3.0.1/16,test1,6.6.6.6:1000,Thu Nov  5 15:34:43 2015
GLOBAL STATS
Max bcast / mcast queue length,39
END`

	name := "test1"
	remote := Addr{net.ParseIP("6.6.6.6"), 1000}
	routes := make([]RouteAddr, 3)
	routes[0] = RouteAddr{net.IPNet{net.ParseIP("10.0.0.1"), net.CIDRMask(32, 32)}, false}
	routes[1] = RouteAddr{net.IPNet{net.ParseIP("10.1.0.1"), net.CIDRMask(32, 32)}, true}
	routes[2] = RouteAddr{net.IPNet{net.ParseIP("10.3.0.1"), net.CIDRMask(16, 32)}, false}
	t1 := time.Unix(1446737683, 0) // Thu Nov  5 15:34:43 2015

	s, err := openvpn.Parse(strings.NewReader(f))
	require.Nil(t, err)
	assert.True(t, s.Updated.Equal(t1))

	require.Len(t, s.Clients, 1)
	assert.Equal(t, name, s.Clients[0].CommonName)
	assert.EqualValues(t, remote, s.Clients[0].RealAddress)
	assert.Equal(t, uint64(100), s.Clients[0].BytesReceived, )
	assert.Equal(t, uint64(98), s.Clients[0].BytesSent)
	assert.True(t, s.Clients[0].Since.Equal(t1))

	require.Len(t, s.Routes, 3)
	for i, v := range s.Routes {
		assert.EqualValues(t, routes[i], v.VirtualAddress)
		assert.Equal(t, name, v.CommonName)
		assert.EqualValues(t, remote, v.RealAddress)
		assert.True(t, v.LastRef.Equal(t1))
	}

	assert.Equal(t, uint64(39), s.MaxQueue)
}
