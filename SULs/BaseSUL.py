import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse
from util import make_request_with_retry, pretty_print_request, pretty_print_response
from aalpy.base import SUL

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
        self.parsed_params_implicit = {
            'response_type': 'token id_token', # Default response type
        }
        self.concrete_inputs = []  # HTTP requests
        self.abstract_outputs = []
        self.concrete_outputs = [] # HTTP responses

    def post(self):
        self.s.close()
    
    def _parse_redirect_params(self, r: requests.Response, use_implicit=False):
        location = r.headers.get('Location')
        if not location:
            return
        
        parsed_url = urlparse(location)
        # Grab fragment if present, otherwise use query parameters
        params = ""
        if parsed_url.fragment:
            params = parsed_url.fragment
        else:
            params = parsed_url.query

        # Manually parse without URL decoding
        if params:
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if 'error' in key.lower():
                        # Skip error parameters, as these are not relevant for the learning and would just add noise
                        continue
                    if use_implicit:
                        self.parsed_params_implicit[key] = value
                    else:
                        self.parsed_params[key] = value
    
    def _abstract_output(self, r: requests.Response):
        raise NotImplementedError("Subclasses must implement this method.")

    def _make_request(self, method, url, parse_redirect_params=False, parse_implicit=False, headers=None, auth=None, **kwargs):
        r = make_request_with_retry(self.s, method, url, proxies=self.proxies, verify=False, headers=headers, auth=auth, **kwargs)
        if parse_redirect_params:
            self._parse_redirect_params(r, use_implicit=parse_implicit)
        self.concrete_inputs.append(pretty_print_request(r.request))
        self.concrete_outputs.append(pretty_print_response(r))
        abstract_out = self._abstract_output(r)
        self.abstract_outputs.append(abstract_out)
        return abstract_out