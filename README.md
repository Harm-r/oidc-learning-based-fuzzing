# oidc-learning-based-fuzzing

OpenID Connect / OAuth 2.0 learning-based fuzzer written during my Master's thesis at the T&I Incubator at GÉANT. Combines [learning-based fuzzing from Aichernig et al.](https://doi.org/10.1109/ICST49551.2021.00017) with property-based mutations inspired by [Yang et al.](https://doi.org/10.1145/2897845.2897874). Code is provided as is.

## TODO
- [x] Add command line arguments
- [x] Expand to OIDC flow
- [ ] Automatically parse discovery endpoint
- [ ] Improve fuzzing capabilities
    - [x] URL fuzzer (redirect_uri, request_uri)
        - [x] Basic version: just a list of standard mutations
        - [x] Maybe use https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet instead of redirect-fuzzer?
    - [x] Basic parameter fuzzer:
        - [x] Parameter pollution: duplicate, two different parameters, maybe with arrays? redirect_uri[0]=x,redirect_uri[1]=y?
    - [x] JWT fuzzer (use jwt tool as inspiration)
    - [x] OAuthTester like approach: define properties of parameters and fuzz based on these properties:
        - constant: Compare the values between different sessions and users
        - mandatory parameter: Remove this parameter and randomize its values
        - used for once or multiple times: Substitute the value with an used one and compare the response
        - user-specific: Substitute the value with a fresh one of another user
        - session-specific: Open a new browser and get a fresh value of this parameter to substitute the existing one
    - [x] Fuzz request object
        - [x] Run normal strategies on parameters, put them in request object (e.g. duplicating parameters)
        - [x] Parse duplicated parameters and type juggling into request object, e.g. state=x&state=y -> {"state":"x", "state": "y"}
        - ~[ ] Send malformed JSON~ not interesting, we don't focus on the JSON parser for now
        - [x] send both query parameters and request object, request object should have preference
        - [x] send request object within request object
    - [ ] Smarter scope fuzzing (and some other parameters)
- [x] Fuzz Implicit Flow with mod_auth_openidc
    - [x] Install mod_auth_openidc
    - [x] Learn implicit flow
    - [x] Fuzz implicit flow
- [ ] Lots of mutations fall back to "invalid{param_name}". Add some filtering beforehand to exclude non-meaningful mutations.
