package libtailscale

import "reflect"

func isNil(i interface{}) bool {
    if i == nil {
        return true
    }

    value := reflect.ValueOf(i)
    kind := value.Kind()

    if kind >= reflect.Chan && kind <= reflect.Slice && value.IsNil() {
        return true
    }

    return false
}