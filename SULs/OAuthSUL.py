import requests
import re
from .BaseSUL import BaseSUL

class OAuthSUL(BaseSUL):
    def __init__(self, op_url, rp_url, proxy=None, user="user", password="password"):
        super().__init__(op_url, rp_url, proxy, user, password)
        self.input_al = ["client_sso_login", 
            "client_callback", 
            "client_callback_invalid", 
            # "client_callback_error", 
            "authserver_authorize",
            "authserver_authorize_invalid",
            # "authserver_authorize_invalid_client",
            # "authserver_authorize_invalid_redirect_uri",
            # "authserver_authorize_unsupported_response_type",
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
            # Abstract nonce
            location = re.sub(r'nonce=[A-Za-z0-9_\-\%]+', 'nonce=<NONCE>', location)
            # Abstract access token
            location = re.sub(r'access_token=[A-Za-z0-9_\-\%\.]+', 'access_token=<ACCESS_TOKEN>', location)
            # Abstract id token
            location = re.sub(r'id_token=[A-Za-z0-9_\-\%\.]+', 'id_token=<ID_TOKEN>', location)
            # Expires in is sometimes a second less, so we abstract it as well
            location = re.sub(r'expires_in=[0-9]+', 'expires_in=<EXPIRES_IN>', location)

            # Authorization endpoint should be abstracted, as it may use normal parameters or the request object
            # location = re.sub(r'/authorization\?[^ ]+', '/authorization?<PARAMS>', location)

            # Abstract redirect parameter
            location = re.sub(r'redirect=[A-Za-z0-9_\-\%\.]+', 'redirect=<REDIRECT>', location)

            return f"({r.status_code}, 'Location: {location}')"
        
        if str(r.status_code).startswith('5') or str(r.status_code).startswith('4'):
            return f"Error"
            # Extract content of <p class="message-box error">...</p>
            # match = re.search(r'<p class="message-box error">(.*?)</p>', text, re.DOTALL)
            # if match:
            #     text = match.group(1).strip()
            # match = re.search(r'<title>(.*?)</title>', text, re.DOTALL)
            # if match:
            #     text = match.group(1).strip()
            # text = "OK" if str(r.status_code).startswith('2') else "Error"

        if str(r.status_code).startswith('2'):
            if 'Error' in r.text or '"error"' in r.text:
                return f"Error"
            return f"OK"

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
                url = f"{self.rp_url}/sso_login"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            case "client_callback":
                url = f"{self.rp_url}/callback?code={self.parsed_params.get('code')}&state={self.parsed_params.get('state')}"
                out = self._make_request('GET', url, parse_redirect_params=True)
                if out != "Error":
                    self.used_params['code'] = self.parsed_params.get('code')
                    self.used_params['state'] = self.parsed_params.get('state')
                return out
            
            case "client_callback_invalid":
                url = f"{self.rp_url}/callback?code=invalidcode&state=invalidstate"
                return self._make_request('GET', url)
            
            # case "client_callback_error":
            #     url = f"{self.rp_url}/callback?error=error&state={self.parsed_params.get('state')}"
            #     return self._make_request('GET', url)
            
            case "authserver_authorize":
                url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
                return self._make_request('GET', url, parse_redirect_params=True)

            case "authserver_authorize_invalid":
                url = f"{self.op_url}/authorize?client_id=invalidclient&redirect_uri=invalidredirecturi&response_type=invalidresponsetype&state=invalidstate&scope=invalidscope"
                return self._make_request('GET', url)
            
            # case "authserver_authorize_invalid_client":
            #     url = f"{self.op_url}/authorize?client_id=invalidclient&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
            #     return self._make_request('GET', url, parse_redirect_params=True)
            
            # case "authserver_authorize_invalid_redirect_uri":
            #     url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}"
            #     return self._make_request('GET', url, parse_redirect_params=True)
            
            # case "authserver_authorize_unsupported_response_type":
            #     url = f"{self.op_url}/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type=unsupported&state={self.parsed_params.get('state')}"
            #     return self._make_request('GET', url, parse_redirect_params=True)
            
            case "authserver_login":
                url = f"{self.op_url}/login?redirect=/"
                return self._make_request('POST', url, data={'username': self.user, 'password': self.password})
            
            case "authserver_login_invalid":
                url = f"{self.op_url}/login?redirect=/"
                return self._make_request('POST', url, data={'username': self.user, 'password': 'wrongpassword'})

