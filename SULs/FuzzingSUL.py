from urllib.parse import urlparse

from .OAuthSUL import OAuthSUL

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