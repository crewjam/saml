package saml

type RequestIdCheckFunction func(string) bool

func createDefaultChecker(possibleRequestIDs []string) RequestIdCheckFunction {
	return func(id string) bool {
		for _, possibleRequestID := range possibleRequestIDs {
			if id == possibleRequestID {
				return true
			}
		}
		return false
	}
}
