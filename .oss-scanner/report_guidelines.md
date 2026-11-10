# How we would like reports written

## Layout and length
- Keep a report short: most should fit on one screen. Use these sections, in this order: Summary, Affected code, Impact, Reproduction, Suggested fix.
- Summary: two or three sentences saying what an attacker can do, not how the code is wrong.
- Reproduction: a Go test that fails on the current main, with the file and package it belongs in. Build the input from a fixture in testdata/ where you can, and say which one.

## What every report should state
- The affected package and the public API that reaches the faulty code: for example ServiceProvider.ParseResponse, samlsp.Middleware, x/samlsp, or IdentityProvider.ServeSSO.
- The binding the input arrives through (HTTP-POST, HTTP-Redirect, SimpleSign, SOAP or Artifact), and whether the attacker needs a valid assertion, a captured one, or nothing at all.
- The configuration needed, and whether it is the default. Name each non-default option that must be set, such as AllowIDPInitiated, a SHA-1 opt-in, or a missing ReplayCache.
- The commit you tested against.
- Where the finding concerns spec conformance, the SAML or XML Signature/Encryption section it departs from (for example saml-core §2.5.1.4).

## Style
- One root cause per report. If several call sites share a cause, list them in one report.
- Start the title with the package name, the way our commit subjects do: "sp: ...", "xmlenc: ...", "x/samlsp: ...".
- Plain prose. Quote code and XML in fenced blocks, and keep quoted XML to the elements that matter.
- Say plainly what you did not confirm, rather than hedging every sentence.
