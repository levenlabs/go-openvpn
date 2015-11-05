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
GLOBAL STATS
Max bcast / mcast queue length,39
END`

	s, err := openvpn.Parse(strings.NewReader(f))
	require.Nil(t, err)
	name := "test1"
	remote := Addr{net.ParseIP("6.6.6.6"), 1000}
	t1 := time.Unix(1446737683, 0) // Thu Nov  5 15:34:43 2015
	assert.True(t, s.Updated.Equal(t1))
	require.Len(t, s.Clients, 1)
	assert.Equal(t, s.Clients[0].CommonName, name)
	assert.Equal(t, s.Clients[0].RealAddress.IP, remote.IP)
	assert.Equal(t, s.Clients[0].RealAddress.Port, remote.Port)
	assert.Equal(t, s.Clients[0].BytesReceived, uint64(100))
	assert.Equal(t, s.Clients[0].BytesSent, uint64(98))
	assert.True(t, s.Clients[0].Since.Equal(t1))
	require.Len(t, s.Routes, 1)
	assert.Equal(t, s.Routes[0].VirtualAddress, net.ParseIP("10.0.0.1"))
	assert.Equal(t, s.Routes[0].CommonName, name)
	assert.Equal(t, s.Routes[0].RealAddress.IP, remote.IP)
	assert.Equal(t, s.Routes[0].RealAddress.Port, remote.Port)
	assert.True(t, s.Routes[0].LastRef.Equal(t1))
	assert.Equal(t, s.MaxQueue, uint64(39))
}
