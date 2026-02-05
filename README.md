# oidc-learning-based-fuzzing

## TODO
- [x] Add command line arguments
- [x] Expand to OIDC flow
- [ ] Automatically parse discovery endpoint
- [ ] Improve fuzzing capabilities
    - [ ] URL fuzzer (redirect_uri, request_uri)
        - [ ] Basic version: just a list of standard mutations
    - [ ] Basic parameter fuzzer:
        - [ ] Change casing
        - [ ] Change 1 character
        - [ ] Append a character
        - [ ] Append a special character
        - [ ] Parameter pollution: duplicate, two different parameters, maybe with arrays? redirect_uri[0]=x,redirect_uri[1]=y?
    - [ ] JWT fuzzer (use jwt tool as inspiration)
    - [x] OAuthTester like approach: define properties of parameters and fuzz based on these properties:
        - constant: Compare the values between different sessions and users
        - mandatory parameter: Remove this parameter and randomize its values
        - used for once or multiple times: Substitute the value with an used one and compare the response
        - user-specific: Substitute the value with a fresh one of another user
        - session-specific: Open a new browser and get a fresh value of this parameter to substitute the existing one


SimpleSAMLphp OIDC module test discovery endpoint: https://fuzz1.incubator.geant.org/simplesaml-op/module.php/oidc/.well-known/openid-configuration

Vragen:
- [ ] Restart session and parameters when init flow is called?
- [ ] Should the authorization code be session specific? Authorization Code Injection?  https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5
- [ ] Go over other properties