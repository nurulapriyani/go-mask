// Some of codes from  https://play.golang.org/p/UjkjLDt3vT
// nurul.apriyani
package mask

import (
	"reflect"
	"strings"
	"math"
)

// Mask for masking value
func MaskString(sval string) (string){
	if len(sval) > 0 {
		sval = doMaskValue(sval)
	}
	return sval
}

// Mask for the mask field
func MaskField(obj reflect.Value, i int) (string){
	f := obj.Field(i)
	if reflect.TypeOf(f.Interface()).Kind() == reflect.String {
		sval := f.Interface().(string)
		if strings.ToLower(obj.Type().Field(i).Tag.Get("mask")) == "true" && len(sval) > 0 {
			sval = doMaskValue(sval)
		}
		return sval
	}
	return ""
}

func doMaskValue(val string) string{
	halfMask :=  float64(len(val)) / float64(2)
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

// Mask for mask struct
func Mask(msg interface{}) {
	if msg == nil {
		return
	}
	rv := reflect.ValueOf(msg)
	changerv(rv)
}

func changerv(rv reflect.Value) (reflect.Value){
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	if rv.Kind() == reflect.Map {
		changeMap(rv)
	}

	if rv.Kind() == reflect.Interface {
		rv = rv.Elem()
		changerv(rv)
	}

	if rv.Kind() == reflect.Struct {
		changeStruct(rv)
	}
	if rv.Kind() == reflect.Slice {
		changeSlice(rv)
	}
	return rv
}

func changeMap(rv reflect.Value) {
	for _, e := range rv.MapKeys() {
		val := rv.MapIndex(e).Elem()
		vp := reflect.New(val.Type())
		vp.Elem().Set(val)
		vp.Interface()
		changerv(vp)
		rv.SetMapIndex(e, vp)
	}
}

func changeStruct(rv reflect.Value) {
	if !rv.CanAddr() {
		return
	}
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		switch field.Kind() {
		case reflect.String:
			if strings.ToLower(rv.Type().Field(i).Tag.Get("mask")) == "true" {
				field.SetString(MaskField(rv, i))
			}
		case reflect.Struct, reflect.Ptr, reflect.Interface:
			changerv(field)
		default:
			continue
		}
	}
}

// assumes rv is a slice
func changeSlice(rv reflect.Value) {
	ln := rv.Len()
	for i := 0; i < ln; i++ {
		changerv(rv.Index(i))
	}
}
