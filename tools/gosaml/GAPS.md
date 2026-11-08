# Redesign: what the design shows that the server does not do

The gosaml.dev redesign (eight pages) is implemented. Most of what the
design assumed has been built: see the pull request for the full list.
This file lists what is left, and the places where the code won over
the design.

## Not built

- **Per-login attribute overrides on the login picker.** The design's
  Options disclosure says "Override the NameID, attributes or session
  length for this login". The IdP overrides the NameID format, the
  authentication context and the session length per login; attributes
  are set per user on the IdP page. The copy says what it does. To
  build it: an attributes textarea in the picker's options, parsed like
  the user editor's, merged over the user's attributes in the login
  handler.
- **HTTP exchanges for back-channel calls the server makes.** A log
  entry shows the HTTP request and response it happened in when that
  request came to one of the instance's protocol endpoints. Calls the
  server makes as a client (artifact resolution, SOAP single logout to a
  peer, metadata fetches) are logged without an exchange; the page says
  so. To build it: record the outgoing request and response in the
  instance's HTTP client (a RoundTripper wrapper) and attach them to the
  event, as the inbound recorder does.
- **Signature verdicts for sent messages.** A received message's log
  entry is decoded from the raw request it came in, so its signatures are
  checked. A sent message is kept only as indented XML, which breaks
  signatures, so its entry says "Signatures not checked" instead. To
  build it: keep the exact bytes of sent messages with the event.

## Where the code won over the design

- **Log entry routes** are `/manage/{secret}/log/{id}`, not
  `/sp/{id}/log/{n}`: the log belongs to the management page, whose URL
  is the instance's only key, so entries are reachable only through it.
- **Login picker copy**: see the first item above.
- **Home create blocks** have no profile select: an IdP's profile is
  chosen on its page ("Behave like"), as the design shows there.
- **Result "Show everything"**: every assertion field is shown; there is
  no toggle.
- **About, Who can see what** keeps a row on logs, which the design's
  mock left out: logs hold users' attributes and the HTTP requests.
