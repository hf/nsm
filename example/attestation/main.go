package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"time"
)

func attest(nonce, userData, publicKey []byte) ([]byte, error) {
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		return nil, err
	}

	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if nil != err {
		return nil, err
	}

	if "" != res.Error {
		return nil, errors.New(string(res.Error))
	}

	if nil == res.Attestation || nil == res.Attestation.Document {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}

func main() {
	att, err :=
		attest(
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		)

	fmt.Printf("attestation %v %v\n", base64.StdEncoding.EncodeToString(att), err)

	time.Sleep(5 * time.Minute)
}
