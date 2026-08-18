from urllib.parse import urlparse
from typing import Dict, Optional
import logging
import random

from .OAuthSUL import OAuthSUL
from Fuzzer import Fuzzer, OIDC_PARAMETER_PROPERTIES

class FuzzingSUL(OAuthSUL):
    def __init__(self, op_url, rp_url, proxy=None, user="user", password="password", fuzz_params=None, mutation_strategies=None):
        super().__init__(op_url, rp_url, proxy, user=user, password=password)
        self.fuzz_params = fuzz_params if fuzz_params else ["state", "code", "client_id", "redirect_uri", "response_type", "scope"]
        self.fuzzing_letters = ["client_callback_invalid", "authserver_authorize_invalid"]

        self.fuzzer = Fuzzer(self, mutation_strategies=mutation_strategies)
        self.changed_inputs = [] # Tracks which inputs were fuzzed and how

        # Define which parameters are used in each input letter
        self.letter_params = {
            "client_callback_invalid": ["code", "state"],
            "client_callback_implicit_invalid": ["response_mode", "state", "access_token", "token_type", "expires_in", "id_token"],
            "authserver_authorize_invalid": ["client_id", "redirect_uri", "response_type", "scope", "request"],
        }
    
    def pre(self):
        super().pre()
        self.changed_inputs = []

    def post(self):
        super().post()

    def _fuzz_redirect_uri(self, redirect_uri: str) -> str:
        """Fuzz the redirect_uri with various bypass techniques."""
        if not redirect_uri:
            return "https://evil.com/callback"
        
        parsed_url = urlparse(redirect_uri)

        return parsed_url.scheme + "://" + parsed_url.netloc + ".evil.com"

    def _choose_fuzz_param(self, params: Dict[str, str]) -> Optional[str]:
        """Choose a fuzz parameter only from currently allowed params."""
        fuzz_params = {k: v for k, v in params.items() if k in self.fuzz_params}

        weighted_choices = []
        for key in fuzz_params:
            props = OIDC_PARAMETER_PROPERTIES.get(key)
            weight = len(props) if props else 1
            weighted_choices.extend([key] * weight)

        if not weighted_choices:
            return None
        return random.choice(weighted_choices)
    
    def _build_fuzzed_data(self, base_data: Dict[str, str], fuzz_param: Optional[str] = None, url: Optional[str] = None):
        query_string = '&'.join([f"{k}={v}" for k, v in base_data.items() if k != fuzz_param])
        
        strategy = "no_fuzz"
        fuzzed_value = None
        if fuzz_param and fuzz_param in base_data:
            fuzzed_value, strategy = self.fuzzer.fuzz_parameter(fuzz_param, base_data[fuzz_param])
            if fuzzed_value:  # Only add if the strategy returns a non-empty value
                if query_string:
                    query_string += '&'
                query_string += fuzzed_value
        
        if url:
            return f"{url}?{query_string}", strategy, fuzzed_value
        return query_string, strategy, fuzzed_value

    def _prepare_fuzzing(self, base_data: Dict[str, str], letter: Optional[str] = None, url: Optional[str] = None, fuzz_param: Optional[str] = None):
        """Build fuzzed payload and metadata, or execute fallback when no fuzzing is possible."""
        fuzz_param = self._choose_fuzz_param(base_data) if not fuzz_param else fuzz_param
        if not fuzz_param:
            fallback_result = self._fallback_without_fuzzing(letter) if letter else None
            return None, fallback_result

        fuzzed_data, strategy, fuzzed_value = self._build_fuzzed_data(base_data, fuzz_param=fuzz_param, url=url)
        changed_value = {f'fuzzed_{fuzz_param}_{strategy}': fuzzed_value}
        fuzzed_header = f'{fuzz_param} ({strategy}) -> {fuzzed_value}'
        logging.info(fuzzed_header)
        return (fuzzed_data, changed_value, fuzzed_header), None

    def _fallback_without_fuzzing(self, letter):
        self.changed_inputs.append({})  # No fuzzing for this step
        return super().step(letter)

    def _get_params_with_fallback(self, letter, implicit=False):
        params = self.parsed_params_implicit if implicit else self.parsed_params
        return {k: params.get(k, 'invalid'+k) for k in self.letter_params.get(letter, [])}
    
    
    def step(self, letter):
        """Execute a step and record the concrete fuzzed value."""
        changed_value = None

        match letter:
            case "client_callback_invalid":
                params = self._get_params_with_fallback(letter, implicit=False)
                prepared, fallback_result = self._prepare_fuzzing(params, letter=letter, url=f"{self.rp_url}/callback")
                if fallback_result is not None:
                    return fallback_result
                url, changed_value, fuzzed_header = prepared
                self.changed_inputs.append(changed_value)
                return self._make_request('GET', url, headers={'FUZZED': fuzzed_header})

            case "authserver_authorize_invalid":
                params = self._get_params_with_fallback(letter)
                params_to_use = {k: v for k, v in params.items() if k in ["client_id", "redirect_uri", "response_type", "state", "scope"]}
                params_to_use["response_type"] = "code"
                prepared, fallback_result = self._prepare_fuzzing(params_to_use, letter=letter, url=f"{self.op_url}/authorize")
            
                if fallback_result is not None:
                    return fallback_result
                
                url, changed_value, fuzzed_header = prepared
                self.changed_inputs.append(changed_value)
                return self._make_request('GET', url, parse_redirect_params=True, headers={'FUZZED': fuzzed_header})

            case _:
                # For non-fuzzed inputs, use parent implementation
                return self._fallback_without_fuzzing(letter)