// Some of codes from  https://play.golang.org/p/UjkjLDt3vT
// nurul.apriyani
package mask

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"crypto/rand"
	"fmt"
	"math"
	"reflect"
	"strings"
	"io"
)

const (
	Asterix = "Asterix"
	AESGCM  = "AESGCM"
)

type gcm struct {
	nonce     string
	secretKey string
}

// Mask for masking value
func MaskString(sval string) string {
	if len(sval) > 0 {
		sval = doMaskValue(sval)
	}
	return sval
}

func MaskField(obj reflect.Value, i int, typ string, secretKey string, snonce string) string {
	f := obj.Field(i)
	if reflect.TypeOf(f.Interface()).Kind() == reflect.String {
		sval := f.Interface().(string)
		if strings.ToLower(obj.Type().Field(i).Tag.Get("mask")) == "true" && len(sval) > 0 && typ == AESGCM {
			key, _ := hex.DecodeString(secretKey)
			plaintext := []byte(sval)

			block, err := aes.NewCipher(key)
			if err != nil {
				panic(err.Error())
			}

			aesgcm, err := cipher.NewGCM(block)
			if err != nil {
				panic(err.Error())
			}
			
			nonce := make([]byte, aesgcm.NonceSize())
			if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
				return ""
			}

			ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
			sval = fmt.Sprintf("%x", ciphertext)
		} else if strings.ToLower(obj.Type().Field(i).Tag.Get("mask")) == "true" && len(sval) > 0 {
			sval = doMaskValue(sval)
		}
		return sval

	}

	return ""
}

func doMaskValue(val string) string {
	halfMask := float64(len(val)) / float64(2)
	val = (val)[:int(math.Floor(halfMask))] + asterixString(int(math.Ceil(halfMask)))
	return val
}

func asterixString(sum int) string {
	result := ""
	for i := 0; i < sum; i++ {
		result += "*"
	}
	return result
}

// MaskAESGCM for mask struct use AES-128-GCM
func MaskAESGCM(msg interface{}, secretKey string, nonce string) {
	gcmObj := gcm{
		secretKey: secretKey,
		nonce:     nonce,
	}

	rv := reflect.ValueOf(msg)
	changerv(rv, AESGCM, gcmObj)
}

// Mask for mask struct
func Mask(msg interface{}) {
	rv := reflect.ValueOf(msg)
	changerv(rv, Asterix, gcm{})
}

func changerv(rv reflect.Value, typ string, gcmObj gcm) {
	if rv.Kind() == reflect.Map {
		changeMap(rv, typ, gcmObj)
	}

	if rv.Kind() == reflect.Struct {
		changeStruct(rv, typ, gcmObj)
	}
	if rv.Kind() == reflect.Slice {
		changeSlice(rv, typ, gcmObj)
	}

	if rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		rv = rv.Elem()
		changerv(rv, typ, gcmObj)
	}
}

func changeMap(rv reflect.Value, typ string, gcmObj gcm) {
	for _, e := range rv.MapKeys() {
		val := rv.MapIndex(e).Elem()
		if !val.IsValid() {
			return
		}
		vp := reflect.New(val.Type())
		vp.Elem().Set(val)
		vp.Interface()
		changerv(vp, typ, gcmObj)
		rv.SetMapIndex(e, vp)
	}
}

func changeStruct(rv reflect.Value, typ string, gcmObj gcm) {
	if !rv.CanAddr() {
		return
	}
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		switch field.Kind() {
		case reflect.String:
			field.SetString(MaskField(rv, i, typ, gcmObj.secretKey, gcmObj.nonce))
		case reflect.Struct, reflect.Ptr, reflect.Interface:
			changerv(field, typ, gcmObj)
		default:
			continue
		}
	}
}

// assumes rv is a slice
func changeSlice(rv reflect.Value, typ string, gcmObj gcm) {
	ln := rv.Len()
	for i := 0; i < ln; i++ {
		changerv(rv.Index(i), typ, gcmObj)
	}
}
