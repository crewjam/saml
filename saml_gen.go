package saml

//go:generate bash -c "(awk 'f || /^Package saml/ { f = 1; print }' README.md | sed 's|^## ||g' | sed 's|\\*\\*||g' | sed 's|^|// |g'; echo 'package saml') > saml.go && gofmt -w saml.go"
