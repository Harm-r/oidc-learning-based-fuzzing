import requests
import time
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse, unquote_plus
import re
import argparse
import datetime
import random
import json
import base64
from enum import Enum, auto
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Set, Tuple

from tqdm import tqdm
from aalpy.base import SUL
from aalpy.oracles import RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton, save_automaton_to_file, load_automaton_from_file


requests.packages.urllib3.disable_warnings()


def make_request_with_retry(session, method, url, max_retries=5, **kwargs):
    """Make a request with retry logic for proxy/connection errors."""
    for attempt in range(max_retries):
        try:
            time.sleep(0.1)  # Base delay between all requests
            if method == 'GET':
                return session.get(url, allow_redirects=False, timeout=10, stream=True, **kwargs)
            elif method == 'POST':
                return session.post(url, allow_redirects=False, timeout=10, stream=True, **kwargs)
        except (requests.exceptions.ProxyError, 
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ChunkedEncodingError) as e:
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + (0.1 * attempt)  # Exponential backoff: 1s, 2.1s, 4.2s, 8.3s
                print(f"Connection error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time:.1f}s: {type(e).__name__}")
                time.sleep(wait_time)
                continue
            print(f"Max retries exceeded for {url}")
            raise e
        
def pretty_print_request(req: requests.PreparedRequest):
    out = f"{req.method} {req.url} HTTP/1.1\n"
    for k, v in req.headers.items():
        out += f"{k}: {v}\n"
    if req.body:
        out += "\n"
        out += f"{req.body}\n"
    return out

def pretty_print_response(r: requests.Response):
    out = f"HTTP/1.1 {r.status_code} {r.reason}\n"
    for k, v in r.headers.items():
        out += f"{k}: {v}\n"
    out += "\n"
    out += r.text
    out += "\n"
    return out

def encode_jwt(payload, header=None) -> str:
    """Encode a JWT with the given payload using 'none' algorithm."""
    if isinstance(payload, dict):
        payload_str = json.dumps(payload, separators=(',', ':'))  # Compact encoding
    else:
        payload_str = payload
    if header is None:
        header = {"alg": "none"}
    header = json.dumps(header, separators=(',', ':'))
    return f"{base64.urlsafe_b64encode(header.encode()).rstrip(b'=').decode()}.{base64.urlsafe_b64encode(payload_str.encode()).rstrip(b'=').decode()}."

def decode_jwt(token) -> Dict:
    """Decode a JWT without verifying the signature."""
    try:
        header_b64, payload_b64, signature = token.split('.')
        payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
        return payload_json
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return {}

class BaseSUL(SUL):
    def __init__(self, op_url, rp_url, proxy=None, user="user", password="password"):
        super().__init__()
        self.op_url=op_url
        self.rp_url=rp_url
        self.user = user
        self.password = password
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.proxy = proxy
        self.s = requests.Session()
        self.concrete_inputs = []  # HTTP requests
        self.abstract_outputs = []
        self.concrete_outputs = [] # HTTP responses

    def pre(self):
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1)
        self.s.mount('http://', adapter)
        self.s.mount('https://', adapter)
        self.parsed_params = {
            'response_type': 'code', # Default response type
        }
        self.concrete_inputs = []  # HTTP requests
        self.abstract_outputs = []
        self.concrete_outputs = [] # HTTP responses

    def post(self):
        self.s.close()
    
    def _parse_redirect_params(self, r: requests.Response):
        location = r.headers.get('Location')
        if not location:
            return
        
        parsed_url = urlparse(location)
        # Manually parse without URL decoding
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    self.parsed_params[key] = value
    
    def _abstract_output(self, r: requests.Response):
        raise NotImplementedError("Subclasses must implement this method.")

    def _make_request(self, method, url, parse_redirect_params=False, headers=None, **kwargs):
        r = make_request_with_retry(self.s, method, url, proxies=self.proxies, verify=False, headers=headers, **kwargs)
        if parse_redirect_params:
            self._parse_redirect_params(r)
        self.concrete_inputs.append(pretty_print_request(r.request))
        self.concrete_outputs.append(pretty_print_response(r))
        abstract_out = self._abstract_output(r)
        self.abstract_outputs.append(abstract_out)
        return abstract_out


class OAuthSUL(BaseSUL):
    def __init__(self, op_url, rp_url, proxy=None, user="user", password="password"):
        super().__init__(op_url, rp_url, proxy, user, password)
        self.input_al = ["client_sso_login", 
            "client_callback", 
            "client_callback_invalid_state", 
            "client_callback_error", 
            "authserver_authorize",
            "authserver_authorize_invalid_client",
            "authserver_authorize_invalid_redirect_uri",
            "authserver_authorize_unsupported_response_type",
            "authserver_login",
            "authserver_login_invalid_credentials"
        ]

    def _abstract_output(self, r: requests.Response):
        """
        Abstract away dynamic values in output to make it deterministic.
        Replaces state, code, tokens, etc. with fixed placeholders.
        Returns a string to match the format stored in .dot files.
        """

        text = r.text
        # Abstract state parameter (typically random alphanumeric)
        text = re.sub(r'state=[A-Za-z0-9_\-\%]+', 'state=<STATE>', text)
        # Abstract authorization code
        text = re.sub(r'code=[A-Za-z0-9_\-\%]+', 'code=<CODE>', text)
        # Abstract redirect
        text = re.sub(r'redirect=[A-Za-z0-9_.\-\%]+', 'redirect=<REDIRECT>', text)
        
        # Remove all double quotes, as this breaks the .dot parsing
        text = text.replace('"', '')

        # Escape all special characters (newlines, tabs, etc.) to match .dot file format
        # repr() adds quotes, so we strip them
        text = repr(text)[1:-1]
        
        # Return as string to match the format from loaded .dot files
        return f"({r.status_code}, '{text}')"

    def step(self, letter):
        match letter:
            case "client_sso_login":
                # Clear session and parsed params so that we don't carry over the old parameters from previous steps (like mismatching state)
                self.s = requests.Session()
                self.parsed_params = {
                    'response_type': 'code', # Default response type
                }
                url = f"{self.rp_url}/sso_login"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "client_callback":
                url = f"{self.rp_url}/callback?code={self.parsed_params.get('code')}&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url)
            
            case "client_callback_invalid_state":
                url = f"{self.rp_url}/callback?code={self.parsed_params.get('code')}&state=invalidstate"
                return self._make_request('GET', url)
            
            case "client_callback_error":
                url = f"{self.rp_url}/callback?error=error&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url)
            
            case "authserver_authorize":
                url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_authorize_invalid_client":
                url = f"{self.op_url}/authorize?client_id=invalidclient&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_authorize_invalid_redirect_uri":
                url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_authorize_unsupported_response_type":
                url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type=unsupported&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_login":
                url = f"{self.op_url}/login?redirect=/"
                return self._make_request('POST', url, parse_redirect_params=True, data={'username': self.user, 'password': self.password})
            
            case "authserver_login_invalid_credentials":
                url = f"{self.op_url}/login?redirect=/"
                return self._make_request('POST', url, parse_redirect_params=True, data={'username': self.user, 'password': 'wrongpassword'})


class ProgressSUL(SUL):
    """Wrapper SUL that shows a progress bar based on estimated query count."""
    
    def __init__(self, wrapped_sul, alphabet_size, expected_states=10, max_cex_length=20):
        super().__init__()
        self.wrapped_sul = wrapped_sul
        self.query_count = 0
        self.step_count = 0
        
        avg_query_len = 3
        expected_rounds = 5
        self.estimated_steps = expected_states * alphabet_size * avg_query_len * expected_rounds
        
        self.pbar = tqdm(
            total=self.estimated_steps,
            desc="Learning",
            unit="steps",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} steps [{elapsed}<{remaining}]"
        )
    
    def pre(self):
        self.wrapped_sul.pre()
    
    def post(self):
        self.wrapped_sul.post()
    
    def step(self, letter):
        self.step_count += 1
        self.pbar.update(1)
        
        # Dynamically extend if we exceed estimate
        if self.step_count > self.pbar.total:
            self.pbar.total = int(self.step_count * 1.3)
            self.pbar.refresh()

        return self.wrapped_sul.step(letter)
        
    def close_progress(self):
        self.pbar.close()


class FuzzingSUL(OAuthSUL):
    def __init__(self, op_url, rp_url, proxy=None):
        super().__init__(op_url, rp_url, proxy)
        self.changed_inputs = [] # Tracks which inputs were fuzzed and how

    def pre(self):
        super().pre()
        self.changed_inputs = []

    def _fuzz_redirect_uri(self, redirect_uri: str) -> str:
        """Fuzz the redirect_uri with various bypass techniques."""
        if not redirect_uri:
            return "https://evil.com/callback"
        
        parsed_url = urlparse(redirect_uri)

        return parsed_url.scheme + "://" + parsed_url.netloc + ".evil.com"
    
    def step(self, letter):
        """Execute a step and record the concrete fuzzed value."""
        changed_value = {}
        
        match letter:
            case "authserver_authorize_invalid_redirect_uri":
                # This is the fuzzed input - generate and record concrete value
                fuzzed_uri = self._fuzz_redirect_uri(self.parsed_params.get('redirect_uri'))
                changed_value = {'fuzzed_redirect_uri': fuzzed_uri}
                
                url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={fuzzed_uri}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                abstract_out = self._make_request('GET', url, parse_redirect_params=True)
                self.changed_inputs.append(changed_value)
                return abstract_out
            
            case _:
                self.changed_inputs.append({})  # No fuzzing for this step
                output = super().step(letter)
                return output


class SSPOIDCSUL(BaseSUL):
    def __init__(self, op_url, rp_url, proxy=None, user="student", password="studentpass"):
        super().__init__(op_url, rp_url, proxy, user, password)
        self.input_al = ["client_sso_login", 
            "client_callback", 
            "client_callback_invalid", 
            "client_callback_error", 
            "authserver_authorize",
            "authserver_authorize_invalid",
            "authserver_authorize_request",
            "authserver_authorize_request_invalid",
            "authserver_login",
            "authserver_login_invalid"
        ]
        self.used_params = {}

    def _abstract_output(self, r: requests.Response):
        text = r.text
        
        if str(r.status_code).startswith('3') and "error" in r.headers.get('Location'):
            return f"Error"

        if str(r.status_code).startswith('3'):
            location = r.headers.get('Location', '')
            # Abstract state parameter (typically random alphanumeric)
            location = re.sub(r'state=[A-Za-z0-9_\-\%]+', 'state=<STATE>', location)
            # Abstract authorization code
            location = re.sub(r'code=[A-Za-z0-9_\-\%]+', 'code=<CODE>', location)
            # Abstract AuthState parameter
            location = re.sub(r'AuthState=[A-Za-z0-9_\-\%]+', 'AuthState=<AUTHSTATE>', location)
            # Abstract request object
            location = re.sub(r'request=[A-Za-z0-9_\-\%\.]+', 'request=<REQUEST>', location)

            return f"({r.status_code}, 'Location: {location}')"
        
        if str(r.status_code).startswith('5') or str(r.status_code).startswith('4') or str(r.status_code).startswith('2'):
            return f"Error"
            # Extract content of <p class="message-box error">...</p>
            # match = re.search(r'<p class="message-box error">(.*?)</p>', text, re.DOTALL)
            # if match:
            #     text = match.group(1).strip()
            # match = re.search(r'<title>(.*?)</title>', text, re.DOTALL)
            # if match:
            #     text = match.group(1).strip()
            # text = "OK" if str(r.status_code).startswith('2') else "Error"

        
        # Remove all double quotes, as this breaks the .dot parsing
        text = text.replace('"', '')

        # Escape all special characters (newlines, tabs, etc.) to match .dot file format
        # repr() adds quotes, so we strip them
        text = repr(text)[1:-1]
        
        # Return as string to match the format from loaded .dot files
        return f"({r.status_code}, '{text}')"
    
    def step(self, letter):
        match letter:
            case "client_sso_login":
                # Clear session and parsed params so that we don't carry over the old parameters from previous steps (like mismatching state)
                # self.s = requests.Session()
                # self.parsed_params = {
                #     'response_type': 'code', # Default response type
                # }
                url = f"{self.rp_url}/../test-oidc.php"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "client_callback":
                url = f"{self.rp_url}/module.php/authoauth2/linkback?code={self.parsed_params.get('code')}&state={self.parsed_params.get('state')}"
                out = self._make_request('GET', url)
                if out != "Error":
                    self.used_params['code'] = self.parsed_params.get('code')
                    # TODO: should the state also be invalidated for errors?
                    self.used_params['state'] = self.parsed_params.get('state')
                return out
            
            case "client_callback_invalid":
                url = f"{self.rp_url}/module.php/authoauth2/linkback?code=invalidcode&state=invalidstate"
                return self._make_request('GET', url)
            
            case "client_callback_error":
                url = f"{self.rp_url}/module.php/authoauth2/linkback?error=error&state={self.parsed_params.get('state')}"
                # TODO: should the state be invalidated here? SSP OIDC seems to accept it
                # self.used_params['state'] = self.parsed_params.get('state')
                return self._make_request('GET', url)
            
            case "authserver_authorize":
                url = f"{self.op_url}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}&scope={self.parsed_params.get('scope')}&approval_prompt={self.parsed_params.get('approval_prompt')}"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_authorize_invalid":
                url = f"{self.op_url}/module.php/oidc/authorization?client_id=invalidclient&redirect_uri=invalidredirecturi&response_type=invalidresponsetype&state=invalidstate&scope=invalidscope&approval_prompt=invalidprompt"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_authorize_request":
                params = {
                    'client_id': self.parsed_params.get('client_id'),
                    'redirect_uri': self.parsed_params.get('redirect_uri'),
                    'response_type': self.parsed_params.get('response_type'),
                    'state': self.parsed_params.get('state'),
                    'scope': self.parsed_params.get('scope'),
                }
                params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
                request_object = encode_jwt(params)
                url = f"{self.op_url}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&scope=openid&request={request_object}"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_authorize_request_invalid":
                url = f"{self.op_url}/module.php/oidc/authorization?client_id=invalidclient&scope=openid&request=invalidrequest"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_login":
                url = f"{self.op_url}/module.php/core/loginuserpass?AuthState={self.parsed_params.get('AuthState')}"
                self.used_params['AuthState'] = self.parsed_params.get('AuthState')
                return self._make_request('POST', url, parse_redirect_params=True, data={'username': self.user, 'password': self.password})
            
            case "authserver_login_invalid":
                url = f"{self.op_url}/module.php/core/loginuserpass?AuthState={self.parsed_params.get('AuthState')}"
                self.used_params['AuthState'] = self.parsed_params.get('AuthState')
                return self._make_request('POST', url, parse_redirect_params=True, data={'username': self.user, 'password': 'wrongpassword'})


class Prop(Enum):
    CONSTANT = auto()
    MANDATORY = auto()
    ONCE = auto()
    USER_SPECIFIC = auto()
    SESSION_SPECIFIC = auto()
    URL = auto()
    REQUEST_OBJECT = auto()


# Parameter property mappings based on OAuth 2.0 / OIDC spec
OIDC_PARAMETER_PROPERTIES: Dict[str, Set[Prop]] = {
    "state": {Prop.ONCE, Prop.USER_SPECIFIC, Prop.SESSION_SPECIFIC},
    "code": {Prop.MANDATORY, Prop.ONCE},
    "client_id": {Prop.CONSTANT, Prop.MANDATORY},
    "redirect_uri": {Prop.CONSTANT, Prop.URL},
    "response_type": {Prop.CONSTANT, Prop.MANDATORY},
    "scope": {Prop.CONSTANT, Prop.MANDATORY},
    "request": {Prop.REQUEST_OBJECT}
}


class Fuzzer:
    def __init__(self, sul: BaseSUL, fuzz_strategies: Optional[List[str]] = None):
        self.sul = sul
        self.fuzz_strategies = fuzz_strategies
        # Cache for values from other users/sessions
        self.other_user_params: Dict[str, str] = {}
        self.other_session_params: Dict[str, str] = {}
        self.strategies = {
            "constant": self._test_constant_value,
            "omit": self._test_omit_parameter,
            "reuse": self._test_reuse_value,
            "other_user": self._test_other_user_value,
            "other_session": self._test_other_session_value,
            "url": self._test_url,
            "request_object": self._test_request_object,
            "request_object_with_normal_params": self._test_request_object_with_normal_params,
            "request_object_within_request_object": self._test_request_object_within_request_object,
            "type_juggling": self._test_type_juggling,
            "duplication_after": self._test_duplication_after,
            "duplication_before": self._test_duplication_before
        }
        self.fuzz_strategies = [self.strategies[s] for s in fuzz_strategies] if fuzz_strategies else list(self.strategies.values())

        self.default_strategies = [
            self._test_type_juggling,
            self._test_duplication_after,
            # self._test_duplication_before # Only last value is used by SSP OIDC module
        ]
    
    def fuzz_parameter(self, param_name: str, original_value: Optional[str], filter_strategies="default") -> Tuple[str, str]:
        properties = OIDC_PARAMETER_PROPERTIES.get(param_name)

        if not properties:
            return f"{param_name}=invalid" + param_name, "invalid"  # Unknown parameter, return generic invalid value

        fuzz_strategies = self.default_strategies.copy()

        if Prop.CONSTANT in properties:
            fuzz_strategies.append(self._test_constant_value)
        if Prop.MANDATORY in properties:
            fuzz_strategies.append(self._test_omit_parameter)
        if Prop.ONCE in properties:
            fuzz_strategies.append(self._test_reuse_value)
        if Prop.USER_SPECIFIC in properties:
            fuzz_strategies.append(self._test_other_user_value)
        if Prop.SESSION_SPECIFIC in properties:
            fuzz_strategies.append(self._test_other_session_value)
        if Prop.URL in properties:
            fuzz_strategies.append(self._test_url)
        if Prop.REQUEST_OBJECT in properties:
            fuzz_strategies.append(self._test_request_object)
            fuzz_strategies.append(self._test_request_object_with_normal_params)
            fuzz_strategies.append(self._test_request_object_within_request_object)
        
        if filter_strategies == "default":
            # Use the default strategies defined in the constructor
            fuzz_strategies = list(set(fuzz_strategies).intersection(self.fuzz_strategies))
        elif filter_strategies != "all":
            fuzz_strategies = list(set(fuzz_strategies).intersection(filter_strategies))

        strategy = random.choice(fuzz_strategies)

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
        return f"{param_name}={original_value}"
    
    def _test_other_user_value(self, param_name: str, original_value: str) -> str:
        """Test using a value from a different user."""
        tmp_sul = type(self.sul)(self.sul.op_url, self.sul.rp_url, self.sul.proxy, user="employee", password="employeepass")
        tmp_sul.pre()
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
        print("_test_duplication_before generated:", fuzzed_param, "with strategy:", strategy)
        return f"{fuzzed_param}&{param_name}={original_value}"

class FuzzingSSPOIDCSUL(SSPOIDCSUL):
    def __init__(self, op_url, rp_url, proxy=None, user="student", password="studentpass", fuzz_params=None, fuzz_strategies=None):
        super().__init__(op_url, rp_url, proxy, user=user, password=password)
        self.fuzz_params = fuzz_params if fuzz_params else OIDC_PARAMETER_PROPERTIES.keys()
        print(f"Fuzzing parameters: {self.fuzz_params} with strategies: {fuzz_strategies}")

        self.fuzzer = Fuzzer(self, fuzz_strategies=fuzz_strategies)
        self.changed_inputs = [] # Tracks which inputs were fuzzed and how

        # Define which parameters are used in each input letter
        self.letter_params = {
            "client_callback_invalid": ["code", "state"],
            "authserver_authorize_invalid": ["client_id", "redirect_uri", "response_type", "scope"],
            "authserver_authorize_request_invalid": ["client_id", "scope", "request"]
        }

    def pre(self):
        super().pre()
        self.changed_inputs = []
    
    def post(self):
        super().post()
    
    def _build_fuzzed_url(self, base_url: str, params: Dict[str, str], fuzz_param: Optional[str] = None) -> str:
        query_string = '&'.join([f"{k}={v}" for k, v in params.items() if k != fuzz_param])
        
        fuzzed_value = None
        if fuzz_param and fuzz_param in params:
            fuzzed_value, strategy = self.fuzzer.fuzz_parameter(fuzz_param, params[fuzz_param])
            if fuzzed_value:  # Only add if the strategy returns a non-empty value
                if query_string:
                    query_string += '&'
                query_string += fuzzed_value

        return f"{base_url}?{query_string}", strategy, fuzzed_value

    def step(self, letter):
        """Execute a step and record the concrete fuzzed value."""
        changed_value = None

        params = {}
        for param in self.letter_params.get(letter, []):
            params[param] = self.parsed_params.get(param, 'invalid'+param)
        
        fuzz_params = {k: v for k, v in params.items() if k in self.fuzz_params} # Only consider parameters that are in the fuzzing list
        
        weighted_choices = []
        for key in fuzz_params:
            props = OIDC_PARAMETER_PROPERTIES.get(key)
            weighted_choices.extend([key] * len(props))  # Weight by number of properties
        if weighted_choices:
            fuzz_param = random.choice(weighted_choices)
        else:
            self.changed_inputs.append({})  # No fuzzing for this step
            return super().step(letter)

        match letter:
            case "client_callback_invalid":
                url, strategy, fuzzed_value = self._build_fuzzed_url(f"{self.rp_url}/module.php/authoauth2/linkback", params, fuzz_param=fuzz_param)
                changed_value = {f'fuzzed_{fuzz_param}_{strategy}': fuzzed_value}
                self.changed_inputs.append(changed_value)
                return self._make_request('GET', url, headers={'FUZZED': f'{fuzz_param} ({strategy}) -> {fuzzed_value}'})
    
            case "authserver_authorize_invalid":
                url, strategy, fuzzed_value = self._build_fuzzed_url(f"{self.op_url}/module.php/oidc/authorization", params, fuzz_param=fuzz_param)
                changed_value = {f'fuzzed_{fuzz_param}_{strategy}': fuzzed_value}
                self.changed_inputs.append(changed_value)
                return self._make_request('GET', url, parse_redirect_params=True, headers={'FUZZED': f'{fuzz_param} ({strategy}) -> {fuzzed_value}'})
            
            case "authserver_authorize_request_invalid":
                url, strategy, fuzzed_value = self._build_fuzzed_url(f"{self.op_url}/module.php/oidc/authorization", params, fuzz_param="request")
                changed_value = {f'fuzzed_request_{strategy}': fuzzed_value}
                self.changed_inputs.append(changed_value)
                return self._make_request('GET', url, parse_redirect_params=True, headers={'FUZZED': f'request ({strategy}) -> {fuzzed_value}'})
            
            case _:
                # For non-fuzzed inputs, use parent implementation
                self.changed_inputs.append({})  # No fuzzing for this step
                return super().step(letter)


def learn_model(sul, expected_states=10, show_progress=True):
    if show_progress:
        progress_sul = ProgressSUL(
            sul, 
            alphabet_size=len(sul.input_al), 
            expected_states=expected_states,
            max_cex_length=20
        )
        learning_sul = progress_sul
    else:
        learning_sul = sul
        progress_sul = None
    
    eq_oracle = RandomWalkEqOracle(sul.input_al, learning_sul, num_steps=1000, reset_after_cex=False, reset_prob=0.15)
    print("Starting learning...")
    learned_model = run_Lstar(sul.input_al, learning_sul, eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=2)

    if progress_sul:
        progress_sul.close_progress()
        print(f"Actual queries: {progress_sul.query_count}")

    return learned_model


def fuzz_model(fuzzing_sul, learned_model):
    eo = StatePrefixEqOracle(fuzzing_sul.input_al, fuzzing_sul, walks_per_state=20, walk_len=10)
    cex = eo.find_cex(learned_model)
    if cex:
        print("Counterexample found")
        print("Abstract inputs:")
        for val in cex:
            print("\t" + val)
        print()

        print("Changed values during fuzzing:")
        for changed in fuzzing_sul.changed_inputs:
            print("\t" + str(changed))
        print()

        print("HTTP Requests:")
        for concrete in fuzzing_sul.concrete_inputs:
            print(str(concrete))
        print()

        learned_model.reset_to_initial()
        output_base = [learned_model.step(i) for i in cex]

        print("Model Outputs:")
        for output in output_base:
            print("\t" + str(output))
        print()

        print("SUT Abstract Outputs:")
        for output in fuzzing_sul.abstract_outputs:
            print("\t" + str(output))
        print()

        # print("HTTP Responses:")
        # for output in fuzzing_sul.concrete_outputs:
        #     print(str(output))
        # print()


def parse_discovery_endpoint(discovery_url: str):
    r = make_request_with_retry(requests.Session(), 'GET', discovery_url, verify=False)
    return r.json()


def setup_argparse():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    parser = argparse.ArgumentParser(description="Learn and fuzz an OIDC implementation with AALpy")

    parser.add_argument('op_url', type=str, help='Base URL of the OpenID Provider (e.g., http://localhost:5000)')
    parser.add_argument('rp_url', type=str, help='Base URL of the Relying Party (e.g., http://localhost:5001)')

    parser.add_argument('-t', '--target', type=str, help='Target implementation to learn/fuzz (oauth, sspoidc)', choices=['oauth', 'sspoidc'], default='oauth')

    parser.add_argument('-l', '--load-model', type=str, help='Path to load existing model from .dot file, skips learning if provided')
    parser.add_argument('-s', '--save-model', type=str, help='Path to save learned model to .dot file', default=f'{timestamp}.dot')
    parser.add_argument('-nv', '--no-visualize', action='store_true', help='Do not visualize the learned model as a PDF')
    parser.add_argument('--only-learn', action='store_true', help='Only perform learning, skip fuzzing')
    parser.add_argument('-p', '--proxy', type=str, help='Proxy URL to use for requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-e', '--expected-states', type=int, default=10, help='Expected number of states (for progress bar estimation)')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar')

    parser.add_argument('--fuzz-params', nargs='+', help='List of parameters to fuzz')
    parser.add_argument('--fuzz-strategies', nargs='+', help='List of strategies to use for fuzzing, space-separated (e.g. constant omit reuse other_user other_session url type_juggling duplication_after duplication_before)')

    return parser


if __name__ == "__main__":
    parser = setup_argparse()
    args = parser.parse_args()

    if args.load_model:
        learned_model = load_automaton_from_file(args.load_model, automaton_type='mealy', compute_prefixes=True)
    else:
        if args.target == 'oauth':
            sul = OAuthSUL(args.op_url, args.rp_url, proxy=args.proxy)
            learned_model = learn_model(sul, expected_states=args.expected_states, show_progress=not args.no_progress)
        elif args.target == 'sspoidc':
            sul = SSPOIDCSUL(args.op_url, args.rp_url, proxy=args.proxy)
            learned_model = learn_model(sul, expected_states=args.expected_states, show_progress=not args.no_progress)
        else:
            raise ValueError(f"Unsupported target: {args.target}")

        if args.save_model:
            save_automaton_to_file(learned_model, args.save_model)
    
    if not args.no_visualize:
        visualize_automaton(learned_model, path=args.save_model.rsplit('.', 1)[0], file_type='pdf')

    if not args.only_learn:
        if args.target == 'oauth':
            fuzzing_sul = FuzzingSUL(args.op_url, args.rp_url, proxy=args.proxy)
            fuzz_model(fuzzing_sul, learned_model)
        elif args.target == 'sspoidc':
            fuzzing_sul = FuzzingSSPOIDCSUL(args.op_url, args.rp_url, proxy=args.proxy, fuzz_params=args.fuzz_params, fuzz_strategies=args.fuzz_strategies)    
            fuzz_model(fuzzing_sul, learned_model)