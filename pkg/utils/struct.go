package utils

import (
	"encoding/json"
	"reflect"
)

func CopyStruct(src, dest any) error {
	if data, err := json.Marshal(src); err != nil {
		return err
	} else {
		return json.Unmarshal(data, dest)
	}
}

func CopyNonZeroFields(src, dst any) {
	dstVal := reflect.ValueOf(dst).Elem()
	srcVal := reflect.ValueOf(src).Elem()

	for i := 0; i < srcVal.NumField(); i++ {
		srcField := srcVal.Field(i)
		if !isZeroValue(srcField) {
			dstVal.Field(i).Set(srcField)
		}
	}
}

func isZeroValue(v reflect.Value) bool {
	zero := reflect.Zero(v.Type())
	return reflect.DeepEqual(v.Interface(), zero.Interface())
}
