# oidc-learning-based-fuzzing

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
    - [ ] JWT fuzzer (use jwt tool as inspiration)
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
    - [ ] authorization request during fuzzing just excludes state parameter now, why? include it again
- [ ] Fuzz Implicit Flow with mod_auth_openidc
    - [ ] Install mod_auth_openidc
    - [ ] Learn implicit flow
    - [ ] Fuzz implicit flow


SimpleSAMLphp OIDC module test discovery endpoint: https://fuzz1.incubator.geant.org/simplesaml-op/module.php/oidc/.well-known/openid-configuration

Vragen:
- [ ] Restart session and parameters when init flow is called?
    - Call init only once at the start in pre()
- [ ] Should the authorization code be session specific? Authorization Code Injection?  https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5
- [ ] Go over other properties

Remove progress bar? 
Read https://blog.syss.com/posts/browser_swapping/
Document all found implementation bugs for developers (definitely document browser swapping attack!)
Create cleaned-up version of state machines
Type juggling: state[] and state=1&state=2, also in the ID token, in json duplicating as well
Test request parameter (also duplicating parameters)
https://pushsecurity.com/blog/consentfix#id-how-consentfix-works

TODO: should the state be invalidated in client_callback_error? SSP seems to accept it