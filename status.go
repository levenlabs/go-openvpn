package openvpn

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"fmt"
)

// Represents an INET address with an IP and port
type Addr struct {
	IP   net.IP
	Port int
}

// Represents an route address with an IP and mask
type RouteAddr struct {
	net.IPNet

	// Remote means it was learned via the remote host
	// The server is forwarding this route to that host
	Remote bool
}

// Represents a OpenVPN client
type Client struct {
	CommonName    string
	RealAddress   Addr
	BytesReceived uint64
	BytesSent     uint64
	Since         time.Time
}

// Represents a OpenVPN route
type Route struct {
	VirtualAddress RouteAddr
	CommonName     string
	RealAddress    Addr
	LastRef        time.Time
}

// Represents the OpenVPN status at a point in time
type Status struct {
	Updated  time.Time
	Clients  []Client
	Routes   []Route
	MaxQueue uint64
}

type readState int

const (
	stateUnknown = iota
	stateClients
	stateRoutes
	stateStats
	stateEnd
)

func parseTime(text string) (time.Time, error) {
	return time.Parse("Mon Jan 2 15:04:05 2006", text)
}

func parseAddr(text string) (Addr, error) {
	a := Addr{}
	h, p, err := net.SplitHostPort(text)
	if err != nil {
		return a, err
	}
	a.IP = net.ParseIP(h)
	if a.IP == nil {
		return a, errors.New("Invalid IP encountered")
	}
	a.Port, err = strconv.Atoi(p)
	if err != nil {
		return a, err
	}
	return a, nil
}

func parseRouteAddr(text string) (RouteAddr, error) {
	r := RouteAddr{}
	// detect if this is a remote addr
	if strings.HasSuffix(text, "C") {
		text = strings.TrimSuffix(text, "C")
		r.Remote = true
	}
	// for some reason ipm.IP is 16 bytes for an IPv4, but ip is 4 bytes
	// so we use ip instead
	ip, ipm, err := net.ParseCIDR(text)
	if err == nil {
		r.IP = ip
		r.Mask = ipm.Mask
		return r, nil
	}

	//it might not be a CIDR and instead just an IP
	r.IP = net.ParseIP(text)
	if r.IP == nil {
		return r, err
	}

	r.Mask = net.CIDRMask(32, 8 * net.IPv4len)
	if r.IP.To4() == nil {
		r.Mask = net.CIDRMask(128, 8 * net.IPv6len)
	}
	return r, nil
}

func (s *Status) parseUpdated(parts []string) error {
	if parts[0] == "Updated" {
		t, err := parseTime(parts[1])
		if err == nil {
			s.Updated = t
		}
		return err
	}
	return nil
}

func (s *Status) parseUnknown(text string) (readState, error) {
	var cs readState
	var err error
	if text == "END" {
		cs = stateEnd
	} else if text == "" {
		cs = stateUnknown
	} else if strings.Contains(text, "CLIENT LIST") {
		cs = stateClients
	} else if strings.Contains(text, "ROUTING TABLE") {
		cs = stateRoutes
	} else if strings.Contains(text, "GLOBAL STATS") {
		cs = stateStats
	} else if strings.HasPrefix(text, "Updated,") {
		s.Updated, err = parseTime(text[8:])
	} else {
		err = errors.New("Unexpected header text")
	}
	return cs, err
}

var timeType = reflect.TypeOf(time.Time{})
var addrType = reflect.TypeOf(Addr{})
var netIPType = reflect.TypeOf(net.IP{})
var routeAddrType = reflect.TypeOf(RouteAddr{})

func parseStructParts(v reflect.Value, parts []string) error {
	var f reflect.Value
	for i := 0; i < v.NumField() && i < len(parts); i += 1 {
		f = v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.Uint64:
			p, err := strconv.ParseUint(parts[i], 10, 64)
			if err != nil {
				return err
			}
			f.SetUint(p)
		case reflect.Int64:
			p, err := strconv.ParseInt(parts[i], 10, 64)
			if err != nil {
				return err
			}
			f.SetInt(p)
		case reflect.String:
			f.SetString(parts[i])
		default:
			t := f.Type()
			switch {
			case t.AssignableTo(timeType):
				p, err := parseTime(parts[i])
				if err != nil {
					return err
				}
				f.Set(reflect.ValueOf(p))
			case t.AssignableTo(addrType):
				p, err := parseAddr(parts[i])
				if err != nil {
					return err
				}
				f.Set(reflect.ValueOf(p))
			case t.AssignableTo(netIPType):
				p := net.ParseIP(parts[i])
				if p == nil {
					return errors.New("Invalid IP encountered")
				}
				f.Set(reflect.ValueOf(p))
			case t.AssignableTo(routeAddrType):
				p, err := parseRouteAddr(parts[i])
				if err != nil {
					return err
				}
				f.Set(reflect.ValueOf(p))
			default:
				return errors.New("Unknown type encountered in struct")
			}
		}
	}
	return nil
}

func (s *Status) parseClient(text string) error {
	parts := strings.Split(text, ",")
	c := Client{}
	v := reflect.ValueOf(&c).Elem()
	err := parseStructParts(v, parts)
	if err != nil {
		//detect column header line
		//todo: better detect this
		if parts[0] == "Common Name" {
			return nil
		}
		return err
	}
	s.Clients = append(s.Clients, c)
	return nil
}

func (s *Status) parseRoutes(text string) error {
	parts := strings.Split(text, ",")
	c := Route{}
	v := reflect.ValueOf(&c).Elem()
	err := parseStructParts(v, parts)
	if err != nil {
		//detect column header line
		//todo: better detect this
		if parts[0] == "Virtual Address" {
			return nil
		}
		return err
	}
	s.Routes = append(s.Routes, c)
	return nil
}

func (s *Status) parseStats(text string) error {
	parts := strings.Split(text, ",")
	if strings.Contains(parts[0], "queue length") {
		p, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return err
		}
		s.MaxQueue = p
	}
	return nil
}

// Parses an io.Reader into a Status
func Parse(r io.Reader) (*Status, error) {
	s := &Status{}
	scanner := bufio.NewScanner(r)
	var t string
	var err error
	var cs readState
	line := 0
	for cs < stateEnd && scanner.Scan() {
		line++
		t = scanner.Text()
		//first try and parse unknown/headers
		if cs2, err2 := s.parseUnknown(t); err2 == nil {
			// only update state if its known
			if cs2 > stateUnknown {
				cs = cs2
			}
			//if we succeeded with parsing, skip this line
			continue
		}
		switch cs {
		case stateClients:
			err = s.parseClient(t)
		case stateRoutes:
			err = s.parseRoutes(t)
		case stateStats:
			err = s.parseStats(t)
		}
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error on line %d: %s", line, err))
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Helper that reads a file into Parse
func ParseFile(path string) (*Status, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return Parse(file)
}
