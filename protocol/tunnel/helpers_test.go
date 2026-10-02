package tunnel

import "runtime"

func runtimeNumGoroutine() int { return runtime.NumGoroutine() }
