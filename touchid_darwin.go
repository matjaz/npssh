//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

// Returns 1 = approved, 0 = denied/cancelled/timeout, -1 = no auth available.
static int npssh_authenticate(const char *reason, int timeoutSecs) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		NSError *err = nil;
		// Touch ID, Apple Watch, or login password as fallback.
		LAPolicy policy = LAPolicyDeviceOwnerAuthentication;
		if (![ctx canEvaluatePolicy:policy error:&err]) {
			return -1;
		}
		__block int result = 0;
		dispatch_semaphore_t sema = dispatch_semaphore_create(0);
		NSString *r = [NSString stringWithUTF8String:reason];
		[ctx evaluatePolicy:policy localizedReason:r reply:^(BOOL success, NSError *e) {
			result = success ? 1 : 0;
			dispatch_semaphore_signal(sema);
		}];
		long timedOut = dispatch_semaphore_wait(sema,
			dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeoutSecs * NSEC_PER_SEC));
		if (timedOut != 0) {
			[ctx invalidate];
			return 0;
		}
		return result;
	}
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func authenticate(reason string) (bool, error) {
	cs := C.CString(reason)
	defer C.free(unsafe.Pointer(cs))
	switch C.npssh_authenticate(cs, 60) {
	case 1:
		return true, nil
	case -1:
		return false, errors.New("no Touch ID / device authentication available")
	default:
		return false, nil
	}
}
