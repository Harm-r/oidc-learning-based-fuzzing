import requests
import re
from .BaseSUL import BaseSUL

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

