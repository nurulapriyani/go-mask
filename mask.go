// Some of codes from  https://play.golang.org/p/UjkjLDt3vT
// nurul.apriyani
package mask

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
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

func MaskField(obj reflect.Value, i int, typ string, secretKey string) string {
	f := obj.Field(i)
	if reflect.TypeOf(f.Interface()).Kind() == reflect.String {
		sval := f.Interface().(string)
		if strings.ToLower(obj.Type().Field(i).Tag.Get("mask")) == "true" && len(sval) > 0 && typ == AESGCM {
			plaintext := []byte(sval)

			block, err := aes.NewCipher([]byte(secretKey))
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
	words := strings.Fields(val)
	lenWords := len(words)
	
	result := ""
	if lenWords == 1 {
		lenVal := len(val)
		halfMask := int(math.Ceil(float64(lenVal) / float64(3)))
		result = (val)[:halfMask] + asterixString(lenVal - halfMask)
	} else {
		for _, elem := range words {
			result += elem[:1] + asterixString(len(elem) - 1) + " "
		}
		result = result[:len(result)-1]
	}
	return result
}

func asterixString(sum int) string {
	result := ""
	for i := 0; i < sum; i++ {
		result += "*"
	}
	return result
}

// MaskAESGCM for mask struct use AES-128-GCM
func MaskAESGCM(msg interface{}, secretKey string) {
	gcmObj := gcm{
		secretKey: secretKey,
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
			field.SetString(MaskField(rv, i, typ, gcmObj.secretKey))
		case reflect.Struct, reflect.Ptr, reflect.Slice, reflect.Interface, reflect.Map:
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
