package saml

import (
	"net/url"
	"testing"

	"gotest.tools/assert"
)

func TestGetOriginalQueryParam(t *testing.T) {
	t.Run("query param not found", func(t *testing.T) {
		assert.Equal(t, getRawQueryParam("", "test"), "")
	})

	t.Run("query param found", func(t *testing.T) {
		assert.Equal(t, getRawQueryParam("test=1", "test"), "1")
	})

	t.Run("query param found with &", func(t *testing.T) {
		assert.Equal(t, getRawQueryParam("test=1&test2=2", "test"), "1")
	})

	t.Run("query param found with & and other params", func(t *testing.T) {
		assert.Equal(t, getRawQueryParam("test=1&test2=2&test3=3", "test"), "1")
	})

	t.Run("query param found with encoded samlresponse", func(t *testing.T) {
		url, err := url.Parse("/saml/logoutResponse/bkwiatm923wdmnkssrwx?SAMLResponse=fVLBbqQwDP0VlDuEEEJKxCCt2stI7WWn6mEvK5OYLiokCIcyn7%2fMzFaruVSKojzLz37PTkMwjbN5Du9hjT%2bR5uAJk%2bPTgf2uXC50p3Uq%2byJPS3iw6YOSkApV6r4QQqEuWPKGCw3BH1iR5Sw5Eq149BTBxz2UFyrNVSr0q1Amr%2faTVZX%2bxZInpDh4iFfmnxhnMpw7%2fMQxzLhkn10484syPt4J493HNkCc6kJubvIfRMt23rv6r4TXcGCDS62TUNquQOxkUaNynUNRiVKIvnOu68GCA1fu8s%2fT6Mlch3Bg6%2bJNABrIeJiQTLTm9OPl2ezWzLyEGGwYWdtcTS436vckIMLlYpK1XyYpUrYN3oWNMo%2bRuxp6KXqVSq10WuL%2bqqWuL1cvrayghpI3%2fNazbW7rOkWIK92jx%2bAweYNxxe817bvZs81ptRaJGG%2bb66T%2fF%2f0H779E%2bxc%3d&Signature=pJQ9%2ff1UbS88s5T5FUCsE9Alej9rmAdlrd64m4RUKTf5WON3v3H7wI1sMfDyfYQDXZYCtz%2b0txQ7ai9xGxoJIXIMEVKCAQXatdL04shef1DPJ%2f7hk5FtGQviOLeoSAk6fRRw72iLMcZb9m7q89wS4F6Si1VCSS4%2bBOqZvRu6qdHVW496nNh8t5RlfPfuix7XpmWaEpoGEqM3Jl06AqaWyYn5V0K6LIHevCLl6D2QDkeTl5QT6VhiHcFFC%2b%2bYZBTTfMlet6cF6u7IuHhCowk73Jm4goFBStG%2b3gd%2bIxLOez%2bfoCqlX8i68KBqKhktOqJHKGzsTPZ3MEJNSedGl507wQ%3d%3d&SigAlg=http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256#")
		assert.NilError(t, err)

		assert.Equal(t, getRawQueryParam(url.RawQuery, "SAMLResponse"), "fVLBbqQwDP0VlDuEEEJKxCCt2stI7WWn6mEvK5OYLiokCIcyn7%2fMzFaruVSKojzLz37PTkMwjbN5Du9hjT%2bR5uAJk%2bPTgf2uXC50p3Uq%2byJPS3iw6YOSkApV6r4QQqEuWPKGCw3BH1iR5Sw5Eq149BTBxz2UFyrNVSr0q1Amr%2faTVZX%2bxZInpDh4iFfmnxhnMpw7%2fMQxzLhkn10484syPt4J493HNkCc6kJubvIfRMt23rv6r4TXcGCDS62TUNquQOxkUaNynUNRiVKIvnOu68GCA1fu8s%2fT6Mlch3Bg6%2bJNABrIeJiQTLTm9OPl2ezWzLyEGGwYWdtcTS436vckIMLlYpK1XyYpUrYN3oWNMo%2bRuxp6KXqVSq10WuL%2bqqWuL1cvrayghpI3%2fNazbW7rOkWIK92jx%2bAweYNxxe817bvZs81ptRaJGG%2bb66T%2fF%2f0H779E%2bxc%3d")
		assert.Equal(t, getRawQueryParam(url.RawQuery, "Signature"), "pJQ9%2ff1UbS88s5T5FUCsE9Alej9rmAdlrd64m4RUKTf5WON3v3H7wI1sMfDyfYQDXZYCtz%2b0txQ7ai9xGxoJIXIMEVKCAQXatdL04shef1DPJ%2f7hk5FtGQviOLeoSAk6fRRw72iLMcZb9m7q89wS4F6Si1VCSS4%2bBOqZvRu6qdHVW496nNh8t5RlfPfuix7XpmWaEpoGEqM3Jl06AqaWyYn5V0K6LIHevCLl6D2QDkeTl5QT6VhiHcFFC%2b%2bYZBTTfMlet6cF6u7IuHhCowk73Jm4goFBStG%2b3gd%2bIxLOez%2bfoCqlX8i68KBqKhktOqJHKGzsTPZ3MEJNSedGl507wQ%3d%3d")
		assert.Equal(t, getRawQueryParam(url.RawQuery, "SigAlg"), "http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256")
	})
}
