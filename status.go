// Package openvpn provides various methods for parsing and interacting with
// the OpenVPN server.
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

// readState represents the current seciton/state of the Status as we
// are parsing it
type readState int
const (
	stateUnknown = iota
	stateClients
	stateRoutes
	stateStats
	stateEnd
)

// Represents the OpenVPN status at a point in time
type Status struct {
	Updated  time.Time
	Clients  []Client
	Routes   []Route
	MaxQueue uint64
	state    readState
}

// parseFn is the type returned from parseLine and is used to further
// process the line
type parseFn func(*Status, string) error

// EOF is returned when the end of the file is reached in parseLine
var EOF = errors.New("EOF reached")

// parseTime parses a string date time following the format:
// Mon Jan 2 15:04:05 2006
// it returns a Time struct
func parseTime(text string) (time.Time, error) {
	return time.Parse("Mon Jan 2 15:04:05 2006", text)
}

// parseAddr parses a string address and returns the resulting Addr
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

// parseRouteAddr parses a string route address and returns the resulting
// RouteAddr struct
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

var timeType = reflect.TypeOf(time.Time{})
var addrType = reflect.TypeOf(Addr{})
var netIPType = reflect.TypeOf(net.IP{})
var routeAddrType = reflect.TypeOf(RouteAddr{})

// parseStructParts takes a struct and fills in the fields based on reflection
// and the order of the []string slice passed in
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

// parseNothing is a placeholder function that does nothing
func parseNothing(s *Status, text string) error {
	return nil
}

// parseUpdated parses the "Updated," line
func parseUpdated(s *Status, text string) error {
	if text[0:7] == "Updated" {
		t, err := parseTime(text[8:])
		if err == nil {
			s.Updated = t
		}
		return err
	}
	return nil
}

// parseClient parses lines in the CLIENT LIST section
func parseClient(s *Status, text string) error {
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

// parseRoute parses lines in the ROUTING TABLE section
func parseRoute(s *Status, text string) error {
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

// parseStat parses lines in the GLOBAL STATS section
func parseStat(s *Status, text string) error {
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

// parseLine accepts a string and returns the appropriate parse* function
// for detailed, specific parsing of the line
func (s *Status) parseLine(text string) (parseFn, error) {
	var err error
	// for all these section headers we want to return parseNothing since we
	// just want to set the state from the header not actually process anything
	fn := parseNothing
	if text == "END" || text == "" {
		s.state = stateEnd
		err = EOF
	} else if strings.Contains(text, "CLIENT LIST") {
		s.state = stateClients
	} else if strings.Contains(text, "ROUTING TABLE") {
		s.state = stateRoutes
	} else if strings.Contains(text, "GLOBAL STATS") {
		s.state = stateStats
	} else if strings.HasPrefix(text, "Updated,") {
		// since updated is in the middle of a section do not change the state
		fn = parseUpdated
	} else {
		// return the appropriate fn for the state we were in as determined by
		// the last header
		switch (s.state) {
		case stateClients:
			fn = parseClient
		case stateRoutes:
			fn = parseRoute
		case stateStats:
			fn = parseStat
		case stateEnd:
			fn = parseNothing
		case stateUnknown:
			fn = parseNothing
			err = errors.New("Unexpected text encountered")
		}
	}

	return fn, err
}

// Parses an io.Reader into a Status
func Parse(r io.Reader) (*Status, error) {
	s := &Status{}
	scanner := bufio.NewScanner(r)
	var t string
	var err error
	var fn parseFn
	line := 0
	for scanner.Scan() {
		line++
		t = scanner.Text()
		fn, err = s.parseLine(t)
		if err == nil {
			// parse the line using the returned function from parseLine
			err = fn(s, t)
		}
		if err != nil {
			if err == EOF {
				break
			}
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
