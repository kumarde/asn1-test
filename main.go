/*
* ZGrab Copyright 2015 Regents of the University of Michigan
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not
* use this file except in compliance with the License. You may obtain a copy
* of the License at http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
* implied. See the License for the specific language governing
* permissions and limitations under the License.
 */

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/kumarde/asn1-test/asn1"
	"github.com/kumarde/asn1-test/crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"time"
)

type InputFormatType int

const (
	InputFormatBase64 InputFormatType = iota
	InputFormatPEM    InputFormatType = iota
)

var inputFormatArg string

type validity struct {
	NotBefore, NotAfter time.Time
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func scannerSplitPEM(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		return size, data[:size], nil
	}
	return 0, nil, nil
}

func main() {
	flag.StringVar(&inputFormatArg, "format", "pem", "one of {pem, base64}")
	flag.Parse()

	inputFormatArg = strings.ToLower(inputFormatArg)
	//log.SetLevel(log.InfoLevel)

	var inputFormat InputFormatType
	var splitter bufio.SplitFunc
	switch inputFormatArg {
	case "pem":
		inputFormat = InputFormatPEM
		splitter = scannerSplitPEM
	case "base64":
		inputFormat = InputFormatBase64
		splitter = bufio.ScanLines
	default:
		//log.Fatalf("invalid --format: provided %s", inputFormatArg)
	}

	if flag.NArg() != 1 {
		//log.Fatal("no path to certificate provided")
	}

	filename := flag.Arg(0)
	f, err := os.Open(filename)
	if err != nil {
		//log.Fatalf("could not open file %s: %s", filename, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(splitter)

	for scanner.Scan() {
		var certBytes []byte
		switch inputFormat {
		case InputFormatPEM:
			p, _ := pem.Decode(scanner.Bytes())
			if p == nil {
				//log.Warnf("could not parse pem")
				continue
			}
			certBytes = p.Bytes
		case InputFormatBase64:
			b := scanner.Bytes()
			certBytes = make([]byte, base64.StdEncoding.DecodedLen(len(b)))
			n, err := base64.StdEncoding.Decode(certBytes, b)
			if err != nil {
				//log.Warnf("could not decode base64: %s", err)
				continue
			}
			certBytes = certBytes[0:n]
		default:
			panic("unreachable")
		}
		var cert certificate
		_, err := asn1.Unmarshal(certBytes, &cert)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("All good.")
		}
	}
}
