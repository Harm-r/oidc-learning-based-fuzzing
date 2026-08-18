from tqdm import tqdm
from aalpy.base import SUL

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