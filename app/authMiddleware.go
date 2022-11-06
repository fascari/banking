package app

import (
	"github.com/fascari/banking-lib/errs"
	"net/http"
	"strings"

	"banking/domain"

	"github.com/gorilla/mux"
)

type AuthMiddleware struct {
	repo domain.AuthRepository
}

func (a AuthMiddleware) authorizationHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentRoute := mux.CurrentRoute(r)
			currentRouteVars := mux.Vars(r)
			authHeader := r.Header.Get("Authorization")

			if authHeader == "" {
				writeResponse(w, http.StatusUnauthorized, "missing token")
				return
			}

			token := getTokenFromHeader(authHeader)

			isAuthorized := a.repo.IsAuthorized(token, currentRoute.GetName(), currentRouteVars)

			if isAuthorized {
				next.ServeHTTP(w, r)
				return
			}

			appError := errs.AppError{Code: http.StatusForbidden, Message: "Unauthorized"}
			writeResponse(w, appError.Code, appError.AsMessage())
		})
	}
}

func getTokenFromHeader(header string) string {
	/*
	   token is coming in the format as below
	   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50cyI6W.yI5NTQ3MCIsIjk1NDcyIiw"
	*/
	splitToken := strings.Split(header, "Bearer")
	if len(splitToken) == 2 {
		return strings.TrimSpace(splitToken[1])
	}
	return ""
}
