package frontend

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/Azure/ARO-HCP/internal/api/arm"
)

func MiddlewarePanic(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func() {
		if e := recover(); e != nil {
			logger := LoggerFromContext(r.Context())
			logger.Error(fmt.Sprintf("panic: %#v\n%s\n", e, string(debug.Stack())))
			arm.WriteInternalServerError(w)
		}
	}()

	next(w, r)
}
