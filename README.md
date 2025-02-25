tc [![PkgGoDev](https://pkg.go.dev/badge/github.com/bestateless/go-tc)](https://pkg.go.dev/github.com/bestateless/go-tc) [![Go Report Card](https://goreportcard.com/badge/github.com/bestateless/go-tc)](https://goreportcard.com/report/github.com/bestateless/go-tc) [![GitHub Actions](https://github.com/bestateless/go-tc/workflows/Go/badge.svg?branch=master)](https://github.com/bestateless/go-tc/actions) [![Coverage Status](https://coveralls.io/repos/github/florianl/go-tc/badge.svg)](https://coveralls.io/github/florianl/go-tc)
==
This is a work in progress version of `tc`.  It provides a [C](https://en.wikipedia.org/wiki/C_(programming_language))-binding free API to the [netlink](http://man7.org/linux/man-pages/man7/netlink.7.html) based [traffic control system](http://man7.org/linux/man-pages/man8/tc.8.html) of [rtnetlink](http://man7.org/linux/man-pages/man7/rtnetlink.7.html).

## Example

```golang
func main() {
	// open a rtnetlink socket
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

    // get all the qdiscs from all interfaces
	qdiscs, err := rtnl.Qdisc().Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get qdiscs: %v\n", err)
		return
	}

	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get interface from id %d: %v", qdisc.Ifindex, err)
			return
		}
		fmt.Printf("%20s\t%s\n", iface.Name, qdisc.Kind)
	}
}
```

## Requirements

* A version of Go that is [supported by upstream](https://golang.org/doc/devel/release.html#policy)

## Privileges

This package processes information directly from the kernel and therefore it requires special privileges. You can provide this privileges by adjusting the `CAP_NET_ADMIN` capabilities.
```
	setcap 'cap_net_admin=+ep' /your/executable
```
