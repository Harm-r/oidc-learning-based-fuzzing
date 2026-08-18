from enum import Enum, auto
import random
from typing import Dict, Set, List, Optional, Tuple
from urllib.parse import urlparse, unquote_plus

from util import encode_jwt, decode_jwt
from SULs.BaseSUL import BaseSUL
from SULs.SSPOIDCSUL import SSPOIDCSUL


class Prop(Enum):
    CONSTANT = auto()
    MANDATORY = auto()
    ONCE = auto()
    USER_SPECIFIC = auto()
    SESSION_SPECIFIC = auto()
    FLOW_SPECIFIC = auto()
    URL = auto()
    REQUEST_OBJECT = auto()
    TOKEN = auto()


# Parameter property mappings based on OAuth 2.0 / OIDC spec
OIDC_PARAMETER_PROPERTIES: Dict[str, Set[Prop]] = {
    "state": {Prop.MANDATORY, Prop.ONCE, Prop.USER_SPECIFIC, Prop.SESSION_SPECIFIC, Prop.FLOW_SPECIFIC},
    "code": {Prop.MANDATORY, Prop.ONCE},
    "client_id": {Prop.CONSTANT, Prop.MANDATORY, Prop.FLOW_SPECIFIC},
    "redirect_uri": {Prop.CONSTANT, Prop.URL, Prop.FLOW_SPECIFIC},
    "response_type": {Prop.CONSTANT, Prop.MANDATORY, Prop.FLOW_SPECIFIC},
    "scope": {Prop.CONSTANT, Prop.MANDATORY},
    "request": {Prop.REQUEST_OBJECT},
    "nonce": {Prop.ONCE, Prop.MANDATORY, Prop.USER_SPECIFIC, Prop.SESSION_SPECIFIC},
    "response_mode": {Prop.CONSTANT, Prop.MANDATORY},
    "token_type": {Prop.CONSTANT, Prop.MANDATORY},
    "expires_in": {Prop.CONSTANT, Prop.MANDATORY},
    "access_token": {Prop.ONCE, Prop.USER_SPECIFIC, Prop.SESSION_SPECIFIC, Prop.TOKEN},
    "id_token":  {Prop.ONCE, Prop.USER_SPECIFIC, Prop.SESSION_SPECIFIC, Prop.TOKEN}
}


class Fuzzer:
    def __init__(self, sul: BaseSUL, mutation_strategies: Optional[List[str]] = None):
        self.sul = sul
        self.mutation_strategies = mutation_strategies
        # Cache for values from other users/sessions
        self.other_user_params: Dict[str, str] = {}
        self.other_session_params: Dict[str, str] = {}
        self.strategies = {
            "constant": self._test_constant_value,
            "omit": self._test_omit_parameter,
            "reuse": self._test_reuse_value,
            "other_user": self._test_other_user_value,
            "other_session": self._test_other_session_value,
            "other_flow": self._test_other_flow_value,
            "other_param": self._test_other_param_value,
            # "append_param": self._test_append_param_value,
            "url": self._test_url,
            "request_object": self._test_request_object,
            "request_object_with_normal_params": self._test_request_object_with_normal_params,
            "request_object_within_request_object": self._test_request_object_within_request_object,
            "jwt_signature_validation": self._test_jwt_signature_validation,
            "jwt_null_signature": self._test_jwt_null_signature,
            "jwt_alg_none": self._test_jwt_alg_none,
            "jwt_alg_confusion": self._test_jwt_alg_confusion,
            "jwt_jwk_spoofing": self._test_jwt_jwk_spoofing,
            "type_juggling": self._test_type_juggling,
            "duplication_after": self._test_duplication_after,
            "duplication_before": self._test_duplication_before
        }
        self.mutation_strategies = [self.strategies[s] for s in mutation_strategies] if mutation_strategies else list(self.strategies.values())

        if type(self.sul) == SSPOIDCSUL:
            self.default_strategies = [
                self._test_type_juggling,
                self._test_duplication_after,
                # self._test_duplication_before # Only last value is used by SSP OIDC module
                self._test_other_param_value,
                # self._test_append_param_value
            ]
        else:
            self.default_strategies = [
                # self._test_type_juggling, # No type juggling in Shib
                self._test_duplication_after,
                # self._test_duplication_before # Only last value is used by SSP OIDC module
                self._test_other_param_value,
                # self._test_append_param_value
            ]

    
    def fuzz_parameter(self, param_name: str, original_value: Optional[str], filter_strategies="default") -> Tuple[str, str]:
        properties = OIDC_PARAMETER_PROPERTIES.get(param_name)

        if not properties:
            return f"{param_name}=invalid" + param_name, "invalid"  # Unknown parameter, return generic invalid value

        mutation_strategies = self.default_strategies.copy()

        if Prop.CONSTANT in properties:
            mutation_strategies.append(self._test_constant_value)
        if Prop.MANDATORY in properties:
            mutation_strategies.append(self._test_omit_parameter)
        if Prop.ONCE in properties:
            mutation_strategies.append(self._test_reuse_value)
        if Prop.USER_SPECIFIC in properties:
            mutation_strategies.append(self._test_other_user_value)
        if Prop.SESSION_SPECIFIC in properties:
            mutation_strategies.append(self._test_other_session_value)
        if Prop.FLOW_SPECIFIC in properties:
            mutation_strategies.append(self._test_other_flow_value)
        if Prop.URL in properties:
            mutation_strategies.append(self._test_url)
        if Prop.REQUEST_OBJECT in properties:
            mutation_strategies.append(self._test_request_object)
            mutation_strategies.append(self._test_request_object_with_normal_params)
            mutation_strategies.append(self._test_request_object_within_request_object)
        if Prop.TOKEN in properties:
            mutation_strategies.append(self._test_jwt_signature_validation)
            mutation_strategies.append(self._test_jwt_null_signature)
            mutation_strategies.append(self._test_jwt_alg_none)
            mutation_strategies.append(self._test_jwt_alg_confusion)
            mutation_strategies.append(self._test_jwt_jwk_spoofing)

        if filter_strategies == "default":
            # Use the default strategies defined in the constructor
            mutation_strategies = list(set(mutation_strategies).intersection(self.mutation_strategies))
        elif filter_strategies != "all":
            mutation_strategies = list(set(mutation_strategies).intersection(filter_strategies))

        if not mutation_strategies:
            return f"{param_name}=invalid" + param_name, "invalid"  # No applicable strategies, return generic invalid value
        
        strategy = random.choice(mutation_strategies)

        return strategy(param_name, original_value), strategy.__name__

    def _test_constant_value(self, param_name: str, original_value: str) -> str:
        """Test if a constant parameter can be changed."""
        return f"{param_name}={original_value[:-1]}X"  # Simple modification to make it invalid

    def _test_omit_parameter(self, param_name: str, original_value: str) -> None:
        """Test omitting a mandatory parameter."""
        return ""
    
    def _test_reuse_value(self, param_name: str, original_value: str) -> str:
        """Test reusing a value that should be single-use."""
        if param_name in self.sul.used_params and self.sul.used_params[param_name]:
            return f"{param_name}={self.sul.used_params[param_name]}"
        return f"{param_name}=invalid{param_name}"
    
    def _test_other_user_value(self, param_name: str, original_value: str) -> str:
        """Test using a value from a different user."""
        tmp_sul = type(self.sul)(self.sul.op_url, self.sul.rp_url, self.sul.proxy, user="employee", password="employeepass")
        tmp_sul.pre()

        if param_name in ["nonce", "access_token", "id_token"]:
            tmp_sul.step("client_sso_login_implicit")
            tmp_sul.step("authserver_authorize_implicit")
            tmp_sul.step("authserver_login")
            tmp_sul.step("authserver_authorize_implicit")
            other_value = tmp_sul.parsed_params_implicit.get(param_name)
        else:
            tmp_sul.step("client_sso_login")
            tmp_sul.step("authserver_authorize")
            tmp_sul.step("authserver_login")
            tmp_sul.step("authserver_authorize")
            other_value = tmp_sul.parsed_params.get(param_name)
        
        tmp_sul.post()
        
        if other_value:
            return f"{param_name}={other_value}"
        else:
            raise ValueError(f"No other user value found for parameter: {param_name}")

    def _test_other_session_value(self, param_name: str, original_value: str) -> str:
        """Test using a value from a different session."""
        tmp_sul = type(self.sul)(self.sul.op_url, self.sul.rp_url, self.sul.proxy, user=self.sul.user, password=self.sul.password)
        tmp_sul.pre()

        if param_name in ["nonce", "access_token", "id_token"]:
            tmp_sul.step("client_sso_login_implicit")
            tmp_sul.step("authserver_authorize_implicit")
            tmp_sul.step("authserver_login")
            tmp_sul.step("authserver_authorize_implicit")
            other_value = tmp_sul.parsed_params_implicit.get(param_name)
        else:
            tmp_sul.step("client_sso_login")
            tmp_sul.step("authserver_authorize")
            tmp_sul.step("authserver_login")
            tmp_sul.step("authserver_authorize")
            other_value = tmp_sul.parsed_params.get(param_name)
        
        tmp_sul.post()

        if other_value:
            return f"{param_name}={other_value}"
        else:
            raise ValueError(f"No other session value found for parameter: {param_name}")
    
    def _test_other_flow_value(self, param_name: str, original_value: str) -> str:
        """Change a parameter to one that is parsed from a different flow."""
        if original_value in self.sul.parsed_params.values():
            return f"{param_name}={self.sul.parsed_params_implicit.get(param_name, 'invalid' + param_name)}"
        elif original_value in self.sul.parsed_params_implicit.values():
            return f"{param_name}={self.sul.parsed_params.get(param_name, 'invalid' + param_name)}"
        else:
            return f"{param_name}=invalid{param_name}"

    def _test_other_param_value(self, param_name: str, original_value: str) -> str:
        """Change a parameter to a value from a different parameter."""
        all_params = list(self.sul.parsed_params.values()) + list(self.sul.parsed_params_implicit.values())
        if param_name == 'request':
            # Don't use the request value from the other flow, as this would not trigger an error but just be treated as a different request object
            if 'request' in self.sul.parsed_params_implicit:
                all_params.remove(self.sul.parsed_params_implicit['request'])
            if 'request' in self.sul.parsed_params:
                all_params.remove(self.sul.parsed_params['request'])
        other_values = [v for v in all_params if v != original_value and v is not None]
        if other_values:
            return f"{param_name}={random.choice(other_values)}"
        else:
            return f"{param_name}=invalid{param_name}"
    
    # def _test_append_param_value(self, param_name: str, original_value: str) -> str:
    #     """Append a different valid parameter to the original value."""
    #     all_params = {**self.sul.parsed_params, **self.sul.parsed_params_implicit}
    #     other_params = [f"{k}={v}" for k, v in all_params.items() if v != original_value and v is not None]
    #     if other_params:
    #         return f"{param_name}={original_value}&{random.choice(other_params)}"
    #     else:
    #         return f"{param_name}={original_value}&invalid=invalid{param_name}"

    def _test_url(self, param_name: str, original_value: str) -> str:
        """Fuzz URLS like the redirect_uri with various bypass techniques."""
        if not original_value:
            return f"{param_name}=https://evil.com/callback"
        
        parsed_url = urlparse(original_value)

        with open('portswigger_url_validation_bypass.txt', 'r') as f:
            payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        payload = random.choice(payloads)

        payload = payload.replace("SCHEME", parsed_url.scheme)
        payload = payload.replace("ALLOWED", parsed_url.netloc)
        payload = payload.replace("ATTACKER", "evil.com")
        payload = payload.replace("/PATH", parsed_url.path)

        return f"{param_name}={payload}"
    
    def _test_request_object(self, param_name: str, original_value: str) -> str:
        """Test fuzzing a request object parameter."""
        params = {
            'client_id': self.sul.parsed_params.get('client_id', 'invalid'),
            'redirect_uri': self.sul.parsed_params.get('redirect_uri', 'invalid'),
            'response_type': self.sul.parsed_params.get('response_type', 'invalid'),
            # 'state': self.sul.parsed_params.get('state'), # State is just reflected, not used by the authorization endpoint, so fuzzing it doesn't make a difference
            'scope': self.sul.parsed_params.get('scope', 'invalid'),
        }
        to_fuzz = random.choice(list(params.keys()))
        fuzzed_param, strategy = self.fuzz_parameter(to_fuzz, params[to_fuzz], filter_strategies="all")
        if strategy == "_test_type_juggling":
            value = fuzzed_param.split('=')[1]
            params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
            params[to_fuzz] = [value]
        elif strategy in ["_test_duplication_after", "_test_duplication_before"]:
        # remove params[to_fuzz]
            param1, param2 = fuzzed_param.split('&')
            val1 = unquote_plus(param1.split('=')[1])
            val2 = unquote_plus(param2.split('=')[1])
            params.pop(to_fuzz)
            params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
            params = str(params)
            params = params.replace("'", '"')  # JWT libraries expect double quotes
            params = params[:-1] + f', "{to_fuzz}": {val1}, "{to_fuzz}": {val2}' + params[-1]
        else:
            params[to_fuzz] = fuzzed_param
            params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
        request_object = encode_jwt(params)
        return f"{param_name}={request_object}"

    def _test_request_object_with_normal_params(self, param_name: str, original_value: str) -> str:
        request_obj_param = self._test_request_object(param_name, original_value)
        normal_params = f"client_id={self.sul.parsed_params.get('client_id', 'invalid')}&redirect_uri={self.sul.parsed_params.get('redirect_uri', 'invalid')}&response_type={self.sul.parsed_params.get('response_type', 'invalid')}&scope={self.sul.parsed_params.get('scope', 'invalid')}&state={self.sul.parsed_params.get('state', 'invalid')}"
        return f"{request_obj_param}&{normal_params}"

    def _test_request_object_within_request_object(self, param_name: str, original_value: str) -> str:
        valid_params = {
            'client_id': self.sul.parsed_params.get('client_id', 'invalid'),
            'redirect_uri': self.sul.parsed_params.get('redirect_uri', 'invalid'),
            'response_type': self.sul.parsed_params.get('response_type', 'invalid'),
            # 'state': self.sul.parsed_params.get('state'), # State is just reflected, not used by the authorization endpoint, so fuzzing it doesn't make a difference
            'scope': self.sul.parsed_params.get('scope', 'invalid'),
        }
        valid_params = {k: unquote_plus(v) for k, v in valid_params.items() if v is not None}
        valid_request_object = encode_jwt(valid_params)

        fuzzed_request_object = self._test_request_object(param_name, original_value).split('=')[1]
        decoded_fuzzed = decode_jwt(fuzzed_request_object)
        decoded_fuzzed = decoded_fuzzed[:-1] + f', "request": "{valid_request_object}"' + decoded_fuzzed[-1]
        nested_request_object = encode_jwt(decoded_fuzzed)

        return f"{param_name}={nested_request_object}"

    def _test_jwt_signature_validation(self, param_name: str, original_value: str) -> str:
        return f"{param_name}={original_value[:-1]}X"  # Simple modification to break signature without changing length (to bypass naive checks)

    def _test_jwt_null_signature(self, param_name: str, original_value: str) -> str:
        parts = original_value.split('.')
        if len(parts) != 3:
            return f"{param_name}=invalidjwt"
        return f"{param_name}={parts[0]}.{parts[1]}."

    def _test_jwt_alg_none(self, param_name: str, original_value: str) -> str:
        if not original_value.count('.') == 2:
            return f"{param_name}=invalidjwt"
        payload = decode_jwt(original_value)
        token = encode_jwt(payload)
        return f"{param_name}={token}"

    def _test_jwt_alg_confusion(self, param_name: str, original_value: str) -> str:
        pass

    def _test_jwt_jwk_spoofing(self, param_name: str, original_value: str) -> str:
        pass

    def _test_type_juggling(self, param_name: str, original_value: str) -> str:
        """Test type juggling by changing the parameter to an array"""
        return f"{param_name}[]={original_value}"

    def _test_duplication_after(self, param_name: str, original_value: str) -> str:
        """Test if duplicating a parameter causes issues."""
        filter_strategies = self.strategies.copy()
        filter_strategies.pop("duplication_after")
        filter_strategies.pop("duplication_before")
        filter_strategies.pop("omit")
        fuzzed_param, strategy = self.fuzz_parameter(param_name, original_value, filter_strategies=filter_strategies.values())
        return f"{param_name}={original_value}&{fuzzed_param}"
    
    def _test_duplication_before(self, param_name: str, original_value: str) -> str:
        """Test if duplicating a parameter causes issues."""
        filter_strategies = self.strategies.copy()
        filter_strategies.pop("duplication_after")
        filter_strategies.pop("duplication_before")
        filter_strategies.pop("omit")
        fuzzed_param, strategy = self.fuzz_parameter(param_name, original_value, filter_strategies=filter_strategies.values())
        return f"{fuzzed_param}&{param_name}={original_value}"