//go:build darwin
// +build darwin

package tailchat

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// Forward declare CF types we need
typedef struct CF_BRIDGED_TYPE(id) __CFNotificationCenter * CFNotificationCenterRef;

// Forward declare the functions we need
extern CFNotificationCenterRef CFNotificationCenterGetDarwinNotifyCenter(void);
extern void CFNotificationCenterPostNotification(CFNotificationCenterRef center, CFStringRef name, const void *object, CFDictionaryRef userInfo, Boolean deliverImmediately);
extern void free(void *ptr);

// Helper function to bridge Go string to CFString
static CFStringRef createCFString(const char *text) {
    return CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
}
*/
import "C"
import "unsafe"

func notifyTailchat(eventType string) {
    center := C.CFNotificationCenterGetDarwinNotifyCenter()
    cstr := C.CString("io.cylonix.sase.tailchat." + eventType)
    defer C.free(unsafe.Pointer(cstr))
    
    name := C.createCFString(cstr)
    defer C.CFRelease(C.CFTypeRef(name))
    var nullDict C.CFDictionaryRef
    C.CFNotificationCenterPostNotification(
        center,
        name,
        unsafe.Pointer(nil),
		nullDict,
        C.Boolean(1),
    )
}