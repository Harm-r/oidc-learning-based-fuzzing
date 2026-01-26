# oidc-learning-based-fuzzing

## TODO
- [x] Add command line arguments
- [ ] Expand to OIDC flow
- [ ] Automatically parse discovery endpoint
- [ ] Improve fuzzing capabilities
    - [ ] URL fuzzer (redirect_uri, request_uri)
    - [ ] Basic parameter fuzzer:
        - [ ] Change casing
        - [ ] Change 1 character
        - [ ] Append a character
        - [ ] Append a special character
        - [ ] Parameter pollution: duplicate, two different parameters, maybe with arrays? redirect_uri[0]=x,redirect_uri[1]=y?
    - [ ] JWT fuzzer (use jwt tool as inspiration)
    - [ ] OAuthTester like approach: define properties of parameters and fuzz based on these properties:
        - constant: Compare the values between different sessions and users
        - mandatory parameter: Remove this parameter and randomize its values
        - used for once or multiple times: Substitute the value with an used one and compare the response
        - user-specific: Substitute the value with a fresh one of another user
        - session-specific: Open a new browser and get a fresh value of this parameter to substitute the existing one