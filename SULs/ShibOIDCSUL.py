from urllib.parse import unquote_plus
import re
import random
import requests

from .BaseSUL import BaseSUL
from util import encode_jwt

class ShibOIDCSUL(BaseSUL):
    def __init__(self, op_url, rp_url, proxy=None, user="student", password="studentpass"):
        super().__init__(op_url, rp_url, proxy, user, password)
        self.input_al = ["client_sso_login",
            # "client_sso_login_implicit",
            "client_callback", 
            "client_callback_invalid", 
            # "client_callback_error",
            # "client_callback_implicit",
            # "client_callback_implicit_invalid",
            "authserver_authorize",
            "authserver_authorize_invalid",
            # "authserver_authorize_implicit",
            # "authserver_authorize_request",
            # "authserver_authorize_request_invalid",
            # "authserver_login",
            # "authserver_login_invalid"
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
            location = re.sub(r'/authorization\?[^ ]+', '/authorization?<PARAMS>', location)

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
                url = f"{self.rp_url}/test-oidc.php"
                return self._make_request('GET', url, parse_redirect_params=True)
            
            # case "client_sso_login_implicit":
            #     url = f"{self.rp_url}/../mod_auth_openidc/test-implicit.php"
            #     return self._make_request('GET', url, parse_redirect_params=True, parse_implicit=True)
            
            case "client_callback":
                url = f"{self.rp_url}/redirect_uri?code={self.parsed_params.get('code')}&state={self.parsed_params.get('state')}"
                out = self._make_request('GET', url)
                if out != "Error":
                    self.used_params['code'] = self.parsed_params.get('code')
                    # TODO: should the state also be invalidated for errors?
                    self.used_params['state'] = self.parsed_params.get('state')
                return out
            
            case "client_callback_invalid":
                url = f"{self.rp_url}/redirect_uri?code=invalidcode&state=invalidstate"
                return self._make_request('GET', url)
            
            # case "client_callback_error":
            #     url = f"{self.rp_url}/redirect_uri?error=error&state={self.parsed_params.get('state')}"
            #     # TODO: should the state be invalidated here? SSP OIDC seems to accept it
            #     # self.used_params['state'] = self.parsed_params.get('state')
            #     return self._make_request('GET', url)
            
            # case "client_callback_implicit":
            #     url = f"{self.rp_url}/../mod_auth_openidc/redirect_uri"
            #     data = {
            #         'response_mode': 'fragment',
            #         'state': self.parsed_params_implicit.get('state'),
            #         'access_token': self.parsed_params_implicit.get('access_token'),
            #         'token_type': self.parsed_params_implicit.get('token_type'),
            #         'expires_in': self.parsed_params_implicit.get('expires_in'),
            #         'id_token': self.parsed_params_implicit.get('id_token'),
            #     }
            #     return self._make_request('POST', url, data=data)
            
            # case "client_callback_implicit_invalid":
            #     url = f"{self.rp_url}/../mod_auth_openidc/redirect_uri"
            #     data = {
            #         'response_mode': 'fragment',
            #         'state': 'invalidstate',
            #         'access_token': 'invalidtoken',
            #         'token_type': 'invalidtype',
            #         'expires_in': 'invalid',
            #         'id_token': 'invalidtoken',
            #     }
            #     return self._make_request('POST', url, data=data)
            
            case "authserver_authorize":
                use_request_object = random.choice([True, False])
                if use_request_object:
                    params = {
                        'client_id': self.parsed_params.get('client_id'),
                        'redirect_uri': self.parsed_params.get('redirect_uri'),
                        'response_type': self.parsed_params.get('response_type'),
                        'state': self.parsed_params.get('state'),
                        'scope': self.parsed_params.get('scope'),
                        'nonce': self.parsed_params.get('nonce'),
                    }
                    params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
                    request_object = encode_jwt(params)
                    url = f"{self.op_url}/profile/oidc/authorize?client_id={self.parsed_params.get('client_id')}&scope=openid&request={request_object}&response_type={self.parsed_params.get('response_type')}"
                else:
                    url = f"{self.op_url}/profile/oidc/authorize?client_id={self.parsed_params.get('client_id')}&redirect_uri={self.parsed_params.get('redirect_uri')}&response_type={self.parsed_params.get('response_type')}&state={self.parsed_params.get('state')}&scope={self.parsed_params.get('scope')}&nonce={self.parsed_params.get('nonce')}"
                return self._make_request('GET', url, parse_redirect_params=True, auth=(self.user, self.password))
            
            # case "authserver_authorize_implicit":
            #     use_request_object = random.choice([True, False])
            #     if use_request_object:
            #         params = {
            #             'client_id': self.parsed_params_implicit.get('client_id'),
            #             'redirect_uri': self.parsed_params_implicit.get('redirect_uri'),
            #             'response_type': self.parsed_params_implicit.get('response_type'),
            #             'state': self.parsed_params_implicit.get('state'),
            #             'scope': self.parsed_params_implicit.get('scope'),
            #             'nonce': self.parsed_params_implicit.get('nonce'),
            #         }
            #         params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
            #         request_object = encode_jwt(params)
            #         url = f"{self.op_url}/idp/profile/oidc/authorize?client_id={self.parsed_params_implicit.get('client_id')}&scope=openid&request={request_object}"
            #     else:
            #         url = f"{self.op_url}/idp/profile/oidc/authorize?client_id={self.parsed_params_implicit.get('client_id')}&redirect_uri={self.parsed_params_implicit.get('redirect_uri')}&response_type={self.parsed_params_implicit.get('response_type')}&state={self.parsed_params_implicit.get('state')}&scope={self.parsed_params_implicit.get('scope')}&nonce={self.parsed_params_implicit.get('nonce')}"
            #     return self._make_request('GET', url, parse_redirect_params=True, parse_implicit=True)

            case "authserver_authorize_invalid":
                use_request_object = random.choice([True, False])
                if use_request_object:
                    url = f"{self.op_url}/idp/profile/oidc/authorize?client_id=invalidclient&scope=openid&request=invalidrequest"
                else:
                    url = f"{self.op_url}/idp/profile/oidc/authorize?client_id=invalidclient&redirect_uri=invalidredirecturi&response_type=invalidresponsetype&state=invalidstate&scope=invalidscope&nonce=invalidnonce"
                return self._make_request('GET', url, parse_redirect_params=True, auth=(self.user, self.password))
            
            # case "authserver_authorize_request":
            #     params = {
            #         'client_id': self.parsed_params.get('client_id'),
            #         'redirect_uri': self.parsed_params.get('redirect_uri'),
            #         'response_type': self.parsed_params.get('response_type'),
            #         'state': self.parsed_params.get('state'),
            #         'scope': self.parsed_params.get('scope'),
            #     }
            #     params = {k: unquote_plus(v) for k, v in params.items() if v is not None}
            #     request_object = encode_jwt(params)
            #     url = f"{self.op_url}/module.php/oidc/authorization?client_id={self.parsed_params.get('client_id')}&scope=openid&request={request_object}"
            #     return self._make_request('GET', url, parse_redirect_params=True)
            
            # case "authserver_authorize_request_invalid":
            #     url = f"{self.op_url}/module.php/oidc/authorization?client_id=invalidclient&scope=openid&request=invalidrequest"
            #     return self._make_request('GET', url, parse_redirect_params=True)
            
            # case "authserver_login":
            #     auth_state = self.parsed_params.get('AuthState') or self.parsed_params_implicit.get('AuthState')
            #     url = f"{self.op_url}/module.php/core/loginuserpass?AuthState={auth_state}"
            #     self.used_params['AuthState'] = auth_state
            #     return self._make_request('POST', url, parse_redirect_params=True, data={'username': self.user, 'password': self.password})
            
            # case "authserver_login_invalid":
            #     auth_state = self.parsed_params.get('AuthState') or self.parsed_params_implicit.get('AuthState')
            #     url = f"{self.op_url}/module.php/core/loginuserpass?AuthState={auth_state}"
            #     self.used_params['AuthState'] = auth_state
            #     return self._make_request('POST', url, parse_redirect_params=True, data={'username': self.user, 'password': 'wrongpassword'})
