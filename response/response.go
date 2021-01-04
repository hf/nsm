// Contains constructs commonly used in the NSM response payload.
package response

import (
	"fmt"
	"github.com/fxamacker/cbor/v2"
)

type Digest string
type ErrorCode string

const (
	ECSuccess          ErrorCode = "Success"
	ECInvalidArgument  ErrorCode = "InvalidArgument"
	ECInvalidResponse  ErrorCode = "InvalidResponse"
	ECReadOnlyIndex    ErrorCode = "ReadOnlyIndex"
	ECInvalidOperation ErrorCode = "InvalidOperation"
	ECBufferTooSmall   ErrorCode = "BufferTooSmall"
	ECInputTooLarge    ErrorCode = "InputTooLarge"
	ECInternalError    ErrorCode = "InternalError"

	DigestSHA256 Digest = "SHA256"
	DigestSHA384 Digest = "SHA384"
	DigestSHA512 Digest = "SHA512"
)

type DescribePCR struct {
	Lock bool   `cbor:"lock" json:"lock,omitempty"`
	Data []byte `cbor:"data" json:"data,omitempty"`
}

type ExtendPCR struct {
	Data []byte `cbor:"data" json:"data,omitempty"`
}

type LockPCR struct {
}

type LockPCRs struct {
}

type DescribeNSM struct {
	VersionMajor uint16   `cbor:"version_major" json:"version_major,omitempty"`
	VersionMinor uint16   `cbor:"version_minor" json:"version_minor,omitempty"`
	VersionPatch uint16   `cbor:"version_patch" json:"version_patch,omitempty"`
	ModuleID     string   `cbor:"module_id" json:"module_id,omitempty"`
	MaxPCRs      uint16   `cbor:"max_pcrs" json:"max_pcrs,omitempty"`
	LockedPCRs   []uint16 `cbor:"locked_pcrs" json:"digest,omitempty"`
	Digest       Digest   `cbor:"digest" json:"digest,omitempty"`
}

type Attestation struct {
	Document []byte `cbor:"document" json:"document,omitempty"`
}

type GetRandom struct {
	Random []byte `cbor:"random" json:"random,omitempty"`
}

type Response struct {
	DescribePCR *DescribePCR `json:"DescribePCR,omitempty"`
	ExtendPCR   *ExtendPCR   `json:"ExtendPCR,omitempty"`
	LockPCR     *LockPCR     `json:"LockPCR,omitempty"`
	LockPCRs    *LockPCRs    `json:"LockPCRs,omitempty"`
	DescribeNSM *DescribeNSM `json:"DescribeNSM,omitempty"`
	Attestation *Attestation `json:"Attestation,omitempty"`
	GetRandom   *GetRandom   `json:"GetRandom,omitempty"`

	Error ErrorCode `json:"Error,omitempty"`
}

type mapResponse struct {
	DescribePCR *DescribePCR `cbor:"DescribePCR"`
	ExtendPCR   *ExtendPCR   `cbor:"ExtendPCR"`
	DescribeNSM *DescribeNSM `cbor:"DescribeNSM"`
	Attestation *Attestation `cbor:"Attestation"`
	GetRandom   *GetRandom   `cbor:"GetRandom"`

	Error ErrorCode `cbor:"Error"`
}

func (res *Response) UnmarshalCBOR(data []byte) error {
	// One might try to question the sanity behind this decoding function.
	// Please enjoy this: https://github.com/pyfisch/cbor/blob/2f2d0253e2d30e5ba7812cf0b149838b0c95530d/src/ser.rs#L83-L117
	possiblyString := ""

	err := cbor.Unmarshal(data, &possiblyString)
	if nil != err {
		possiblyMap := mapResponse{}
		err := cbor.Unmarshal(data, &possiblyMap)
		if nil != err {
			return err
		}

		res.DescribePCR = possiblyMap.DescribePCR
		res.ExtendPCR = possiblyMap.ExtendPCR
		res.DescribeNSM = possiblyMap.DescribeNSM
		res.Attestation = possiblyMap.Attestation
		res.GetRandom = possiblyMap.GetRandom
		res.Error = possiblyMap.Error
	}

	if "LockPCR" == possiblyString {
		res.LockPCR = &LockPCR{}
	} else if "LockPCRs" == possiblyString {
		res.LockPCRs = &LockPCRs{}
	} else {
		return fmt.Errorf("Unknown response string-like value %v", possiblyString)
	}

	return nil
}
