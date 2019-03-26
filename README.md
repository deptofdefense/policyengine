# Policy engine [![Build Status](https://travis-ci.com/deptofdefense/policyengine.svg?branch=master)](https://travis-ci.com/deptofdefense/policyengine)


Policy Engine is a authentication/authorization (authx) service that is designed 
to work with [traefik](https://traefik.io/) as a _Forward Auth Provider_.

The overall workflow is to, at the request level, do an evaluation of 
SSO tokens, Webauthn tokens, and authorization check using [Open Poicy Agent](https://www.openpolicyagent.org/).

Both SSO and Webauthn are optional and can be both turned off and directed
at any service which provides those functions. For testing purposes we have been
using [Vouch](https://github.com/vouch/vouch-proxy)  with Google sign-in and the 
demo [Webauth  project by Duo](https://github.com/duo-labs/webauthn.io).

## Getting Started

Policy Engine is a authx mechanism  that is sent a request containing the headers 
to be evaluated and responds with the appropriate HTTP code and redirect URL if 
necessary. It currently supports SSO and Webauthn tokens for authentication 
and Open Policy Agent for authortization. 

### SSO (Vouch)

For SSO we use [Vouch Proxy](https://github.com/vouch/vouch-proxy) which provides 
an abstraction for a number of SSO providers and will do the validation of the
 _Vouch-Token_. 

The internals of Policy Engine were designed to use their suggested setup and only 
the minimal Vouch setup is necessary to have this up and running.

The SSO function can also be disabled by setting the following environment variable.

```
SSOOFF=1
```

### Webauthn (just an example)

For Webauthn we used the Duo example project. This is just for testing but we liked
 the properties of U2F/FIDO and wanted to be able to demostrate it being used 
in real time to provide a security benefit.

We also implemented the internals in a way that the minimal [webauthn.io](https://github.com/duo-labs/webauthn.io) example should work out of the box.

 The U2F can be disabled by setting the following environment variable.

```
U2FOFF=1
```

### Open Policy Agent

Open Policy Agent is a policy engine that evaluates Datalog style rules and uses 
JSON documents as input and data sources. OPA evaluates policy rules by using the 
input and data and returns the result.The input is the AttributeTuple struct which
 is submited via POST to the _opa-endpoint_ and the Policy Engine expects a true/false 
return value.

More documentation can be found at the [OPA](https://www.openpolicyagent.org/) site
 and more examples about our specific implementation can be found in our Access Proxy repo.