import requests
import time
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse
import re
import argparse
import datetime
import random

from tqdm import tqdm
from aalpy.base import SUL
from aalpy.oracles import RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton, save_automaton_to_file, load_automaton_from_file


requests.packages.urllib3.disable_warnings()

def abstract_output(r: requests.Response):
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
    # Abstract access tokens
    # output = re.sub(r'access_token=[A-Za-z0-9_.-]+', 'access_token=<TOKEN>', output)
    # Abstract refresh tokens
    # output = re.sub(r'refresh_token=[A-Za-z0-9_.-]+', 'refresh_token=<REFRESH>', output)
    # Abstract session IDs in cookies or URLs
    # output = re.sub(r'session=[A-Za-z0-9_-]+', 'session=<SESSION>', output)
    
    # Remove all double quotes, as this breaks the .dot parsing
    text = text.replace('"', '')
    
    # Return as string to match the format from loaded .dot files
    return f"({r.status_code}, '{text}')"

def abstract_output_sspoidc(r: requests.Response):
    """
    Abstract away dynamic values in output to make it deterministic.
    Replaces state, code, tokens, etc. with fixed placeholders.
    Returns a string to match the format stored in .dot files.
    """

    text = r.text
    
    if str(r.status_code).startswith('3'):
        location = r.headers.get('Location', '')
        # Abstract state parameter (typically random alphanumeric)
        location = re.sub(r'state=[A-Za-z0-9_\-\%]+', 'state=<STATE>', location)
        # Abstract authorization code
        location = re.sub(r'code=[A-Za-z0-9_\-\%]+', 'code=<CODE>', location)
        # Abstract AuthState parameter
        location = re.sub(r'AuthState=[A-Za-z0-9_\-\%]+', 'AuthState=<AUTHSTATE>', location)

        return f"({r.status_code}, 'Location: {location}')"
    
    if str(r.status_code).startswith('5') or str(r.status_code).startswith('4') or str(r.status_code).startswith('2'):
        # Extract content of <p class="message-box error">...</p>
        match = re.search(r'<p class="message-box error">(.*?)</p>', text, re.DOTALL)
        if match:
            text = match.group(1).strip()
        match = re.search(r'<title>(.*?)</title>', text, re.DOTALL)
        if match:
            text = match.group(1).strip()
        text = "OK" if str(r.status_code).startswith('2') else "Error"
    
    # Remove all double quotes, as this breaks the .dot parsing
    text = text.replace('"', '')
    
    # Return as string to match the format from loaded .dot files
    return f"({r.status_code}, '{text}')"

def make_request_with_retry(session, method, url, max_retries=5, **kwargs):
    """Make a request with retry logic for proxy/connection errors."""
    for attempt in range(max_retries):
        try:
            time.sleep(0.1)  # Base delay between all requests
            if method == 'GET':
                return session.get(url, allow_redirects=False, timeout=10, **kwargs)
            elif method == 'POST':
                return session.post(url, allow_redirects=False, timeout=10, **kwargs)
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

class OAuthSUL(SUL):
    def __init__(self, auth_server_url, client_url, proxy=None):
        super().__init__()
        self.CLIENT_URL=client_url
        self.AUTH_SERVER_URL=auth_server_url
        if proxy:
            self.proxies = {
                "http": proxy,
                "https": proxy
            }
        else:
            self.proxies = None
        self.s = requests.Session()

    def pre(self):
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1)
        self.s.mount('http://', adapter)
        self.s.mount('https://', adapter)
        self.parsed_params = {
            'response_type': 'code', # Default response type
        }

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

    def step(self, letter):
        match letter:
            case "client_sso_login":
                # Clear parsed params so that we don't carry over the old parameters from previous steps (like mismatching state)
                self.parsed_params = {
                    'response_type': 'code', # Default response type
                }
                url = f"{self.CLIENT_URL}/sso_login"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                
                return abstract_output(r)
            
            case "client_callback":
                url = f"{self.CLIENT_URL}/callback?code={self.parsed_params.get('code')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output(r)
            
            case "client_callback_invalid_state":
                url = f"{self.CLIENT_URL}/callback?code={self.parsed_params.get('code')}&state=invalidstate"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output(r)
            
            case "client_callback_error":
                url = f"{self.CLIENT_URL}/callback?error=error&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output(r)
            
            case "authserver_authorize":
                url = f"{self.AUTH_SERVER_URL}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output(r)
            
            case "authserver_authorize_invalid_client":
                url = f"{self.AUTH_SERVER_URL}/authorize?client_id=invalidclient&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output(r)
            
            case "authserver_authorize_invalid_redirect_uri":
                url = f"{self.AUTH_SERVER_URL}/authorize?client_id={self.parsed_params.get('client_id')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output(r)
            
            case "authserver_authorize_unsupported_response_type":
                url = f"{self.AUTH_SERVER_URL}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type=unsupported&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output(r)
            
            case "authserver_login":
                url = f"{self.AUTH_SERVER_URL}/login?redirect=/"
                r = make_request_with_retry(self.s, 'POST', url, data={'username': 'user', 'password': 'password'}, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                
                return abstract_output(r)
            
            case "authserver_login_invalid_credentials":
                url = f"{self.AUTH_SERVER_URL}/login?redirect=/"
                r = make_request_with_retry(self.s, 'POST', url, data={'username': 'user', 'password': 'wrongpassword'}, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output(r)


class ProgressSUL(SUL):
    """Wrapper SUL that shows a progress bar based on estimated query count."""
    
    def __init__(self, wrapped_sul, alphabet_size, expected_states=10, max_cex_length=20):
        super().__init__()
        self.wrapped_sul = wrapped_sul
        self.query_count = 0
        self.step_count = 0
        
        # Estimate: O(n^2 * k * m) where n=states, k=alphabet, m=cex length
        # This is a rough heuristic, actual may vary
        self.estimated_queries = (expected_states ** 2) * alphabet_size * max_cex_length
        
        self.pbar = tqdm(
            total=self.estimated_queries,
            desc="Learning",
            unit="queries",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} queries [{elapsed}<{remaining}]"
        )
    
    def pre(self):
        self.wrapped_sul.pre()
    
    def post(self):
        self.wrapped_sul.post()
    
    def step(self, letter):
        self.step_count += 1
        return self.wrapped_sul.step(letter)
    
    def query(self, word):
        self.query_count += 1
        self.pbar.update(1)
        
        # If we exceed estimate, increase the total dynamically
        if self.query_count > self.pbar.total:
            self.pbar.total = int(self.query_count * 1.5)
            self.pbar.refresh()
        
        return self.wrapped_sul.query(word)
    
    def close_progress(self):
        self.pbar.close()


class FuzzingSUL(OAuthSUL):
    def __init__(self, auth_server_url, client_url, proxy=None):
        super().__init__(auth_server_url=auth_server_url, client_url=client_url, proxy=proxy)
        self.concrete_trace = []  # Stores concrete fuzzed values for reproducibility

    def pre(self):
        super().pre()
        self.concrete_trace = []  # Reset trace on each new run

    def fuzz_redirect_uri(self, redirect_uri: str) -> str:
        """Fuzz the redirect_uri with various bypass techniques."""
        if not redirect_uri:
            return "https://evil.com/callback"
        
        parsed_url = urlparse(redirect_uri)

        return parsed_url.scheme + "://" + parsed_url.netloc + ".evil.com"

    def trace_with_concrete_values(self, letter, concrete_value):
        """Replay a step with specific concrete values for reproducibility."""
        match letter:
            case "authserver_authorize_invalid_redirect_uri":
                if concrete_value and 'fuzzed_redirect_uri' in concrete_value:
                    fuzzed_uri = concrete_value['fuzzed_redirect_uri']
                else:
                    fuzzed_uri = self.fuzz_redirect_uri(self.parsed_params.get('redirect_uri'))
                
                url = f"{self.AUTH_SERVER_URL}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={fuzzed_uri}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                return abstract_output(r)
            
            case _:
                # For non-fuzzed inputs, use parent implementation
                return super().step(letter)
    
    def step(self, letter):
        """Execute a step and record the concrete fuzzed value."""
        concrete_value = None
        
        match letter:
            case "authserver_authorize_invalid_redirect_uri":
                # This is the fuzzed input - generate and record concrete value
                fuzzed_uri = self.fuzz_redirect_uri(self.parsed_params.get('redirect_uri'))
                concrete_value = {'fuzzed_redirect_uri': fuzzed_uri}
                
                url = f"{self.AUTH_SERVER_URL}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={fuzzed_uri}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                
                self.concrete_trace.append(concrete_value)
                return abstract_output(r)
            
            case _:
                # For non-fuzzed inputs, use parent implementation
                self.concrete_trace.append(None)  # No fuzzing for this step
                return super().step(letter)



input_al = ["client_sso_login", 
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


class SSPOIDCSUL(SUL):
    def __init__(self, auth_server_url, client_url, proxy=None):
        super().__init__()
        self.CLIENT_URL=client_url # https://fuzz1.incubator.geant.org/simplesaml-rp
        self.AUTH_SERVER_URL=auth_server_url # https://fuzz1.incubator.geant.org/simplesaml-op
        if proxy:
            self.proxies = {
                "http": proxy,
                "https": proxy
            }
        else:
            self.proxies = None
        self.s = requests.Session()

    def pre(self):
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1)
        self.s.mount('http://', adapter)
        self.s.mount('https://', adapter)
        # Default parameters
        self.parsed_params = {
            'response_type': 'code',
        }

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
    
    def step(self, letter):
        match letter:
            case "client_sso_login":
                # Clear parsed params so that we don't carry over the old parameters from previous steps (like mismatching state)
                self.parsed_params = {
                    'response_type': 'code', # Default response type
                }
                url = f"{self.CLIENT_URL}/../test-oidc.php"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                
                return abstract_output_sspoidc(r)
            
            case "client_callback":
                url = f"{self.CLIENT_URL}/module.php/authoauth2/linkback?code={self.parsed_params.get('code')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output_sspoidc(r)
            
            case "client_callback_invalid_state":
                url = f"{self.CLIENT_URL}/module.php/authoauth2/linkback?code={self.parsed_params.get('code')}&state=invalidstate"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output_sspoidc(r)
            
            case "client_callback_error":
                url = f"{self.CLIENT_URL}/module.php/authoauth2/linkback?error=error&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output_sspoidc(r)
            
            case "authserver_authorize":
                url = f"{self.AUTH_SERVER_URL}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}&scope={self.parsed_params.get('scope')}&approval_prompt={self.parsed_params.get('approval_prompt')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output_sspoidc(r)
            
            case "authserver_authorize_invalid_client":
                url = f"{self.AUTH_SERVER_URL}/module.php/oidc/authorization?client_id=invalidclient&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}&scope={self.parsed_params.get('scope')}&approval_prompt={self.parsed_params.get('approval_prompt')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output_sspoidc(r)
            
            case "authserver_authorize_invalid_redirect_uri":
                url = f"{self.AUTH_SERVER_URL}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}&scope={self.parsed_params.get('scope')}&approval_prompt={self.parsed_params.get('approval_prompt')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output_sspoidc(r)
            
            case "authserver_authorize_unsupported_response_type":
                url = f"{self.AUTH_SERVER_URL}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type=unsupported&state={self.parsed_params.get('state')}&scope={self.parsed_params.get('scope')}&approval_prompt={self.parsed_params.get('approval_prompt')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output_sspoidc(r)
            
            case "authserver_login":
                url = f"{self.AUTH_SERVER_URL}/module.php/core/loginuserpass?AuthState={self.parsed_params.get('AuthState')}"
                r = make_request_with_retry(self.s, 'POST', url, data={'username': 'student', 'password': 'studentpass'}, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                
                return abstract_output_sspoidc(r)
            
            case "authserver_login_invalid_credentials":
                url = f"{self.AUTH_SERVER_URL}/module.php/core/loginuserpass?AuthState={self.parsed_params.get('AuthState')}"
                r = make_request_with_retry(self.s, 'POST', url, data={'username': 'student', 'password': 'wrongpassword'}, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)

                return abstract_output_sspoidc(r)


class FuzzingSSPOIDCSUL(SSPOIDCSUL):
    def __init__(self, auth_server_url, client_url, proxy=None):
        super().__init__(auth_server_url=auth_server_url, client_url=client_url, proxy=proxy)
        self.concrete_trace = []  # Stores concrete fuzzed values for reproducibility
        self.used_params = {}

    def pre(self):
        super().pre()
        self.concrete_trace = []  # Reset trace on each new run
        self.used_params = {}
    
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
                    if key not in self.used_params:
                        self.used_params[key] = []
                    self.used_params[key].append(self.parsed_params.get(key))
                    self.parsed_params[key] = value
    
    def _get_fresh_state(self):
        url = f"{self.CLIENT_URL}/../test-oidc.php"
        temp_s = requests.Session()
        r = make_request_with_retry(temp_s, 'GET', url, proxies=self.proxies, verify=False)
        temp_s.close()
        location = r.headers.get('Location')
        if not location:
            return None
        parsed_url = urlparse(location)
        # Manually parse without URL decoding
        query_params = {}
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
        return query_params.get('state')
    
    def _get_other_user_state(self):
        # TODO
        pass

    def _fuzz_redirect_uri(self, redirect_uri: str) -> str:
        """Fuzz the redirect_uri with various bypass techniques."""
        if not redirect_uri:
            return "https://evil.com/callback"
        
        parsed_url = urlparse(redirect_uri)

        return parsed_url.scheme + "://" + parsed_url.netloc + ".evil.com"

    def trace_with_concrete_values(self, letter, concrete_value):
        """Replay a step with specific concrete values for reproducibility."""
        match letter:
            case "client_callback_invalid_state":
                if concrete_value and 'fuzzed_state' in concrete_value:
                    fuzzed_state = concrete_value['fuzzed_state']
                else:
                    fuzzed_state = ""
                    randval = random.randint(1, 2)
                    if randval == 1:
                        # Use previously used state value
                        fuzzed_state = random.choice(self.used_params.get('state', ['invalidstate']))
                    elif randval == 2:
                        # Get a fresh valid state from a new SSO login
                        fresh_state = self._get_fresh_state()
                        fuzzed_state = fresh_state if fresh_state else "invalidstate"

                url = f"{self.CLIENT_URL}/module.php/authoauth2/linkback?code={self.parsed_params.get('code')}&state={fuzzed_state}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                return abstract_output_sspoidc(r)

            case "authserver_authorize_invalid_redirect_uri":
                if concrete_value and 'fuzzed_redirect_uri' in concrete_value:
                    fuzzed_uri = concrete_value['fuzzed_redirect_uri']
                else:
                    fuzzed_uri = self._fuzz_redirect_uri(self.parsed_params.get('redirect_uri'))
                
                url = f"{self.AUTH_SERVER_URL}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&redirect_uri={fuzzed_uri}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                return abstract_output_sspoidc(r)
            
            case _:
                # For non-fuzzed inputs, use parent implementation
                return super().step(letter)
    
    def step(self, letter):
        """Execute a step and record the concrete fuzzed value."""
        concrete_value = None
        
        match letter:
            case "client_callback_invalid_state":
                fuzzed_state = ""
                randval = random.randint(1, 2)
                if randval == 1:
                    # Use previously used state value
                    fuzzed_state = random.choice(self.used_params.get('state', ['invalidstate']))
                elif randval == 2:
                    # Get a fresh valid state from a new SSO login
                    fresh_state = self._get_fresh_state()
                    fuzzed_state = fresh_state if fresh_state else "invalidstate"

                url = f"{self.CLIENT_URL}/module.php/authoauth2/linkback?code={self.parsed_params.get('code')}&state={fuzzed_state}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)

                self.concrete_trace.append({'fuzzed_state': fuzzed_state})
                return abstract_output_sspoidc(r)
    
            case "authserver_authorize_invalid_redirect_uri":
                # This is the fuzzed input - generate and record concrete value
                fuzzed_uri = self._fuzz_redirect_uri(self.parsed_params.get('redirect_uri'))
                concrete_value = {'fuzzed_redirect_uri': fuzzed_uri}
                
                url = f"{self.AUTH_SERVER_URL}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&redirect_uri={fuzzed_uri}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                r = make_request_with_retry(self.s, 'GET', url, proxies=self.proxies, verify=False)
                self._parse_redirect_params(r)
                
                self.concrete_trace.append(concrete_value)
                return abstract_output_sspoidc(r)
            
            case _:
                # For non-fuzzed inputs, use parent implementation
                self.concrete_trace.append(None)  # No fuzzing for this step
                return super().step(letter)


def learn_model(sul, expected_states=10, show_progress=True):
    if show_progress:
        progress_sul = ProgressSUL(
            sul, 
            alphabet_size=len(input_al), 
            expected_states=expected_states,
            max_cex_length=20
        )
        learning_sul = progress_sul
    else:
        learning_sul = sul
        progress_sul = None
    
    eq_oracle = RandomWalkEqOracle(input_al, learning_sul, num_steps=1000, reset_after_cex=False, reset_prob=0.15)

    print("Starting learning...")
    learned_model = run_Lstar(input_al, learning_sul, eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=2)

    if progress_sul:
        progress_sul.close_progress()
        print(f"Actual queries: {progress_sul.query_count}")

    return learned_model


def fuzz_model(fuzzing_sul, learned_model):
    eo = StatePrefixEqOracle(input_al, fuzzing_sul, walks_per_state=20, walk_len=10)
    cex = eo.find_cex(learned_model)
    if cex:
        print("Counterexample found")
        print("Inputs values", cex)
        print("Concrete values", fuzzing_sul.concrete_trace)

        # Save concrete trace before resetting
        saved_concrete_trace = fuzzing_sul.concrete_trace.copy()

        learned_model.reset_to_initial()
        output_base = [learned_model.step(i) for i in cex]
        
        fuzzing_sul.post()
        fuzzing_sul.pre()

        output_sul = [fuzzing_sul.trace_with_concrete_values(i, c) for i, c in zip(cex, saved_concrete_trace)]

        print("Model Output", output_base)
        print("SUL Output", output_sul)


def parse_discovery_endpoint(discovery_url: str):
    r = make_request_with_retry(requests.Session(), 'GET', discovery_url, verify=False)
    return r.json()


def setup_argparse():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    parser = argparse.ArgumentParser(description="Learn and fuzz an OIDC implementation with AALpy")

    parser.add_argument('auth_server_url', type=str, help='Base URL of the Authorization Server (e.g., http://localhost:5000)')
    parser.add_argument('client_url', type=str, help='Base URL of the Client Application (e.g., http://localhost:5001)')

    parser.add_argument('-t', '--target', type=str, help='Target implementation to learn/fuzz (oauth, sspoidc)', choices=['oauth', 'sspoidc'], default='oauth')

    parser.add_argument('-l', '--load-model', type=str, help='Path to load existing model from .dot file, skips learning if provided')
    parser.add_argument('-s', '--save-model', type=str, help='Path to save learned model to .dot file', default=f'{timestamp}.dot')
    parser.add_argument('-nv', '--no-visualize', action='store_true', help='Do not visualize the learned model as a PDF')
    parser.add_argument('--only-learn', action='store_true', help='Only perform learning, skip fuzzing')
    parser.add_argument('-p', '--proxy', type=str, help='Proxy URL to use for requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-e', '--expected-states', type=int, default=10, help='Expected number of states (for progress bar estimation)')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar')

    return parser


if __name__ == "__main__":
    parser = setup_argparse()
    args = parser.parse_args()

    if args.load_model:
        learned_model = load_automaton_from_file(args.load_model, automaton_type='mealy', compute_prefixes=True)
    else:
        if args.target == 'oauth':
            sul = OAuthSUL(auth_server_url=args.auth_server_url, client_url=args.client_url, proxy=args.proxy)
        elif args.target == 'sspoidc':
            sul = SSPOIDCSUL(auth_server_url=args.auth_server_url, client_url=args.client_url, proxy=args.proxy)
        else:
            raise ValueError(f"Unsupported target: {args.target}")

        learned_model = learn_model(sul, expected_states=args.expected_states, show_progress=not args.no_progress)
        if args.save_model:
            save_automaton_to_file(learned_model, args.save_model)
    
    if not args.no_visualize:
        visualize_automaton(learned_model, path=args.save_model.rsplit('.', 1)[0], file_type='pdf')

    if not args.only_learn:
        if args.target == 'oauth':
            fuzzing_sul = FuzzingSUL(auth_server_url=args.auth_server_url, client_url=args.client_url, proxy=args.proxy)
        elif args.target == 'sspoidc':
            fuzzing_sul = FuzzingSSPOIDCSUL(auth_server_url=args.auth_server_url, client_url=args.client_url, proxy=args.proxy)    
        fuzz_model(fuzzing_sul, learned_model)