package goyubikey

import (
	"time"
	"strconv"
	"io/ioutil"
	"bytes"
	"encoding/base64"
	"sort"
	"crypto/hmac"
	"rand"
	"http"
)

type Yubikey struct {
	id string
	key []byte
}

func NewYubikey(id, key string) *Yubikey {
	keyLen := base64.StdEncoding.DecodedLen(len([]byte(key)))
	y := new(Yubikey)
	y.id = id
	y.key = make([]byte, keyLen)
	base64.StdEncoding.Decode(y.key, []byte(key))
	return y
}

func (y *Yubikey) CheckOTP(otp string) bool {
	nonce := makeNonce()
	timestamp := strconv.Itoa64(time.Seconds())

	r, _, err := http.Get("http://api.yubico.com/wsapi/2.0/verify?id="+y.id+"&otp="+otp+"&nonce="+nonce+"&timestamp="+timestamp)

	if err != nil {
		return false
	}

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return false
	}

	lines := bytes.Split(body, []byte{'\r', '\n'}, -1)

	params := make(map[string]string)

	for _, line := range lines {
		parts := bytes.Split(line, []byte{'='}, 2)
		if len(parts) < 2 {
			continue
		}
		params[string(bytes.TrimSpace(parts[0]))] = string(bytes.TrimSpace(parts[1]))
	}

	theirSig, ok := params["h"]

	if !ok {
		return false
	}

	params["h"] = "", false

	ourSig := y.genSig(params)

	if theirSig != ourSig {
		return false
	}

	if params["status"] != "OK" {
		return false
	}

	return true
}

func (y *Yubikey) genSig(params map[string]string) string {
	keys := make([]string, len(params))
	i := 0
	for k, _ := range params {
		keys[i] = k
		i++
	}
	sort.SortStrings(keys)

	buf := bytes.NewBuffer([]byte{})

	for i, key := range keys {
		buf.WriteString(key+"="+params[key])
		if i != len(keys) - 1 {
			buf.WriteString("&")
		}
	}


	h := hmac.NewSHA1(y.key)

	h.Write(buf.Bytes())

	rawSig := h.Sum()

	sig := make([]byte, base64.StdEncoding.EncodedLen(len(rawSig)))
	base64.StdEncoding.Encode(sig, rawSig)

	return string(sig)
}

func makeNonce() string {

	rand.Seed(time.Seconds())

	nonce := make([]byte, 32)

	for i := 0; i < len(nonce); i++ {
		b := rand.Int() % 52
		if b < 26 {
			b += 65
		} else {
			b += 71
		}
		nonce[i] = byte(b)
	}
	return string(nonce)
}

