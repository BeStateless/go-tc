package tc

import (
	"errors"
	"fmt"

	"github.com/bestateless/go-tc/internal/unix"
	"github.com/mdlayher/netlink"
)

// Filter represents the filtering part of rtnetlink
type Filter struct {
	Tc
}

// Filter allows to read and alter filters
func (tc *Tc) Filter() *Filter {
	return &Filter{*tc}
}

// Add create a new filter
func (f *Filter) Add(info *Object) error {
	if info == nil {
		return ErrNoArg
	}
	options, err := validateFilterObject(unix.RTM_NEWTFILTER, info)
	if err != nil {
		return err
	}
	return f.action(unix.RTM_NEWTFILTER, netlink.Create|netlink.Excl, &info.Msg, options)
}

// Replace add/remove a filter. If the node does not exist yet it is created
func (f *Filter) Replace(info *Object) error {
	if info == nil {
		return ErrNoArg
	}
	options, err := validateFilterObject(unix.RTM_NEWTFILTER, info)
	if err != nil {
		return err
	}
	return f.action(unix.RTM_NEWTFILTER, netlink.Create, &info.Msg, options)
}

// Delete removes a filter
func (f *Filter) Delete(info *Object) error {
	if info == nil {
		return ErrNoArg
	}
	options, err := validateFilterObject(unix.RTM_DELTFILTER, info)
	if err != nil {
		return err
	}
	return f.action(unix.RTM_DELTFILTER, netlink.HeaderFlags(0), &info.Msg, options)
}

// Get fetches all filters
func (f *Filter) Get(i *Msg) ([]Object, error) {
	if i == nil {
		return []Object{}, ErrNoArg
	}
	return f.get(unix.RTM_GETTFILTER, i)
}

func marshalFilterOptions(kind string, info *Object) ([]byte, error) {
	var data []byte
	var err error
	switch kind {
	case "bpf":
		data, err = marshalBpf(info.BPF)
	case "basic":
		data, err = marshalBasic(info.Basic)
	case "cgroup":
		data, err = marshalCgroup(info.Cgroup)
	case "flow":
		data, err = marshalFlow(info.Flow)
	case "flower":
		data, err = marshalFlower(info.Flower)
	case "fw":
		data, err = marshalFw(info.Fw)
	case "route4":
		data, err = marshalRoute4(info.Route4)
	case "rsvp":
		data, err = marshalRsvp(info.Rsvp)
	case "u32":
		data, err = marshalU32(info.U32)
	case "matchall":
		data, err = marshalMatchall(info.Matchall)
	default:
		return []byte{}, fmt.Errorf("can't marshal %s: %w", kind, ErrNotImplemented)
	}
	return data, err
}

func validateFilterObject(action int, info *Object) ([]tcOption, error) {
	options := []tcOption{}
	if info.Ifindex == 0 {
		return options, ErrInvalidDev
	}

	if info.Stats != nil || info.XStats != nil || info.Stats2 != nil {
		return options, ErrInvalidArg
	}

	if info.EgressBlock != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaEgressBlock, Data: uint32Value(info.EgressBlock)})
	}
	if info.IngressBlock != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaIngressBlock, Data: uint32Value(info.IngressBlock)})
	}
	if info.HwOffload != nil {
		options = append(options, tcOption{Interpretation: vtUint8, Type: tcaHwOffload, Data: uint8Value(info.HwOffload)})
	}
	if info.Chain != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaChain, Data: uint32Value(info.Chain)})
	}

	var data []byte
	var err error
	options = append(options, tcOption{Interpretation: vtString, Type: tcaKind, Data: info.Kind})

	if isFilter(info.Kind) {
		data, err = marshalFilterOptions(info.Kind, info)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		if errors.Is(err, ErrNoArg) && action == unix.RTM_DELTFILTER {
			return options, nil
		}
		return options, err
	}
	if len(data) < 1 {
		if action == unix.RTM_NEWTFILTER {
			return options, ErrNoArg
		}
	} else {
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaOptions, Data: data})
	}

	return options, nil
}

func isFilter(f string) bool {
	for _, filter := range []string{"basic", "bpf", "cgroup", "flow", "flower", "fw", "route4", "rsvp", "u32", "matchall"} {
		if f == filter {
			return true
		}
	}
	return false
}
