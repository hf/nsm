// Contains constructs commonly used in the NSM request payload.
package request

type Request interface {
	Encoded() interface{}
}

type DescribePCR struct {
	Index uint16 `cbor:"index"`
}

func (r *DescribePCR) Encoded() interface{} {
	return map[string]*DescribePCR{
		"DescribePCR": r,
	}
}

type ExtendPCR struct {
	Index uint16 `cbor:"index"`
	Data  []byte `cbor:"data"`
}

func (r *ExtendPCR) Encoded() interface{} {
	return map[string]*ExtendPCR{
		"ExtendPCR": r,
	}
}

type LockPCR struct {
	Index uint16 `cbor:"index"`
}

func (r *LockPCR) Encoded() interface{} {
	return map[string]*LockPCR{
		"LockPCR": r,
	}
}

type LockPCRs struct {
	Range uint16 `cbor:"range"`
}

func (r *LockPCRs) Encoded() interface{} {
	return map[string]*LockPCRs{
		"LockPCRs": r,
	}
}

type DescribeNSM struct {
}

func (r *DescribeNSM) Encoded() interface{} {
	return "DescribeNSM"
}

type Attestation struct {
	UserData  []byte `cbor:"user_data"`
	Nonce     []byte `cbor:"nonce"`
	PublicKey []byte `cbor:"public_key"`
}

func (r *Attestation) Encoded() interface{} {
	return map[string]*Attestation{
		"Attestation": r,
	}
}

type GetRandom struct {
}

func (r *GetRandom) Encoded() interface{} {
	return "GetRandom"
}
