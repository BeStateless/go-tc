package tc

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

const (
	tcaGactUnspec = iota
	tcaGactTm
	tcaGactParms
	tcaGactProb
	tcaGactPad
)

// Gact contains attribute of the Gact discipline
type Gact struct {
	Parms       *GactParms
	Tm          *Tcft
	Prob        *GactProb
}

// GactParms include attributes from include/uapi/linux/tc_act/tc_gact.h
type GactParms struct {
	Index   uint32
	Capab   uint32
	Action  uint32
	RefCnt  uint32
	BindCnt uint32
}

// GactProb defines the type of generic action that will be taken
type GactProb struct {
	Ptype       uint16
	Pval        uint16
	Paction     uint64
}

// marshalGact returns the binary encoding of Gact
func marshalGact(info *Gact) ([]byte, error) {
	options := []tcOption{}

	if info == nil {
		return []byte{}, fmt.Errorf("Gact: %w", ErrNoArg)
	}
	// TODO: improve logic and check combinations
	if info.Tm != nil {
		return []byte{}, ErrNoArgAlter
	}
	if info.Parms != nil {
		data, err := marshalStruct(info.Parms)
		if err != nil {
			return []byte{}, err
		}
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaGactParms, Data: data})
	}
	if info.Prob != nil {
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaGactProb, Data: *info.Prob})
	}

	return marshalAttributes(options)
}

// unmarshalGact parses the Gact-encoded data and stores the result in the value pointed to by info.
func unmarshalGact(data []byte, info *Gact) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case tcaGactParms:
			parms := &GactParms{}
			if err := unmarshalStruct(ad.Bytes(), parms); err != nil {
				return err
			}
			info.Parms = parms
		case tcaGactTm:
			tcft := &Tcft{}
			if err := unmarshalStruct(ad.Bytes(), tcft); err != nil {
				return err
			}
			info.Tm = tcft
		case tcaGactProb:
			prob := &GactProb{}
			if err := unmarshalStruct(ad.Bytes(), prob); err != nil {
				return err
			}
			info.Prob = prob
		case tcaGactPad:
			// padding does not contain data, we just skip it
		default:
			return fmt.Errorf("unmarshalGact()\t%d\n\t%v", ad.Type(), ad.Bytes())
		}
	}
	return nil
}
