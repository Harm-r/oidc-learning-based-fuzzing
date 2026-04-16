import requests
import argparse
import datetime
import logging
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from aalpy.oracles import RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton, save_automaton_to_file, load_automaton_from_file
from aalpy.automata.MealyMachine import MealyMachine

from util import make_request_with_retry
from SULs.BaseSUL import BaseSUL
from SULs.ProgressSUL import ProgressSUL
from SULs.OAuthSUL import OAuthSUL
from SULs.SSPOIDCSUL import SSPOIDCSUL
from SULs.ShibOIDCSUL import ShibOIDCSUL
from SULs.FuzzingSUL import FuzzingSUL
from SULs.FuzzingSSPOIDCSUL import FuzzingSSPOIDCSUL
from SULs.FuzzingShibOIDCSUL import FuzzingShibOIDCSUL

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)


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
    logging.info("Starting learning...")
    learned_model = run_Lstar(sul.input_al, learning_sul, eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=2)

    if progress_sul:
        progress_sul.close_progress()
        logging.info(f"Actual queries: {progress_sul.query_count}")

    return learned_model

def print_cex(cex, fuzzing_sul, learned_model):
    logging.info("Counterexample found")
    logging.info("Abstract inputs:")
    for val in cex:
        logging.info(f"\t{val}\n")

    logging.info("Changed values during fuzzing:")
    for changed in fuzzing_sul.changed_inputs:
        logging.info(f"\t{str(changed)}\n")

    logging.info("HTTP Requests:")
    for concrete in fuzzing_sul.concrete_inputs:
        logging.info(f"{str(concrete)}\n")

    learned_model.reset_to_initial()
    output_base = [learned_model.step(i) for i in cex]

    logging.info("Model Outputs:")
    for output in output_base:
        logging.info(f"\t{str(output)}\n")

    logging.info("SUT Abstract Outputs:")
    for output in fuzzing_sul.abstract_outputs:
        logging.info(f"\t{str(output)}\n")

    # logging.info("HTTP Responses:")
    # for output in fuzzing_sul.concrete_outputs:
    #     logging.info(f"\t{str(output)}\n")

def fuzz_model(fuzzing_sul, learned_model):
    eo = StatePrefixEqOracle(fuzzing_sul.input_al, fuzzing_sul, walks_per_state=20, walk_len=10)
    cex = eo.find_cex(learned_model)
    if cex:
        print_cex(cex, fuzzing_sul, learned_model)
    else:
        logging.info("No discrepancies found during fuzzing walks")

def fuzz_model_state_by_state(fuzzing_sul: BaseSUL, learned_model: MealyMachine, mutations_per_letter=20):
    """
    Fuzzes each state of the learned_model individually.
    1. For each state, extract the prefix that leads to it, and walk to it.
    2. Try each fuzzing letter from that state n times.
    3. If the output differs from the learned model's output for that letter, report and exit.
    """
    learned_model.compute_prefixes()
    states = learned_model.states

    total_tests = len(states) * len(fuzzing_sul.fuzzing_letters) * mutations_per_letter
    progress = tqdm(total=total_tests, desc="Fuzzing states", unit="test")

    with logging_redirect_tqdm():
        for i, state in enumerate(states):
            prefix = state.prefix if state.prefix else []
            logging.info(f"==[ Testing state {i+1}/{len(states)} with prefix {prefix} ]==")
            fuzzing_sul.pre()
            for input in prefix:
                fuzzing_sul.step(input)
            learned_model.current_state = state  # Force the learned model to be in the correct state

            for letter in fuzzing_sul.fuzzing_letters:
                logging.info(f"-- Fuzzing input '{letter}' --")
                for _ in range(mutations_per_letter):  # Fuzz each input multiple times
                    progress.update(1)
                    fuzzing_sul.changed_inputs = []  # Reset changed inputs tracking
                    saved_cookies = fuzzing_sul.s.cookies.copy()  # Save session to restore after each mutation
                    output = fuzzing_sul.step(letter)
                    expected_output = learned_model.step(letter)
                    if output != expected_output:
                        cex = list(prefix) + [letter]
                        print_cex(cex, fuzzing_sul, learned_model)
                        return  # Exit on first discrepancy found
                    if learned_model.current_state != state:
                        logging.info(f"State changed during fuzzing, resetting to target state {i+1}")
                        fuzzing_sul.post()
                        fuzzing_sul.pre()
                        for input in prefix:
                            fuzzing_sul.step(input)
                        learned_model.current_state = state  # Force reset to target state
                    fuzzing_sul.s.cookies = saved_cookies  # Restore session to avoid unintended state changes

        fuzzing_sul.post()

def parse_discovery_endpoint(discovery_url: str):
    r = make_request_with_retry(requests.Session(), 'GET', discovery_url, verify=False)
    return r.json()


def setup_argparse():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    parser = argparse.ArgumentParser(description="Learn and fuzz an OIDC implementation with AALpy")

    parser.add_argument('op_url', type=str, help='Base URL of the OpenID Provider (e.g., http://localhost:5000)')
    parser.add_argument('rp_url', type=str, help='Base URL of the Relying Party (e.g., http://localhost:5001)')

    parser.add_argument('-t', '--target', type=str, help='Target implementation to learn/fuzz (oauth, sspoidc, shiboidc)', choices=['oauth', 'sspoidc', 'shiboidc'], default='sspoidc')
    parser.add_argument('-fm', '--fuzzing-mode', type=str, help='Fuzzing mode: walk or statewise', choices=['walk', 'statewise'], default='statewise')

    parser.add_argument('-l', '--load-model', type=str, help='Path to load existing model from .dot file, skips learning if provided')
    parser.add_argument('-s', '--save-model', type=str, help='Path to save learned model to .dot file', default=f'{timestamp}.dot')
    parser.add_argument('-nv', '--no-visualize', action='store_true', help='Do not visualize the learned model as a PDF')
    parser.add_argument('--only-learn', action='store_true', help='Only perform learning, skip fuzzing')
    parser.add_argument('-p', '--proxy', type=str, help='Proxy URL to use for requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-e', '--expected-states', type=int, default=10, help='Expected number of states (for progress bar estimation)')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar')

    parser.add_argument('--fuzz-params', nargs='+', help='List of parameters to fuzz')
    parser.add_argument('--mutation-strategies', nargs='+', help='List of strategies to use for mutation, space-separated (e.g. constant omit reuse other_user other_session url type_juggling duplication_after duplication_before)')

    return parser


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%Y/%m/%d %I:%M:%S')
    parser = setup_argparse()
    args = parser.parse_args()

    if args.load_model:
        learned_model = load_automaton_from_file(args.load_model, automaton_type='mealy', compute_prefixes=True)
    else:
        if args.target == 'oauth':
            sul = OAuthSUL(args.op_url, args.rp_url, proxy=args.proxy)
        elif args.target == 'sspoidc':
            sul = SSPOIDCSUL(args.op_url, args.rp_url, proxy=args.proxy)
        elif args.target == 'shiboidc':
            sul = ShibOIDCSUL(args.op_url, args.rp_url, proxy=args.proxy)
        else:
            raise ValueError(f"Unsupported target: {args.target}")

        learned_model = learn_model(sul, expected_states=args.expected_states, show_progress=not args.no_progress)

        if args.save_model:
            save_automaton_to_file(learned_model, args.save_model)
    
    if not args.no_visualize:
        visualize_automaton(learned_model, path=args.save_model.rsplit('.', 1)[0], file_type='pdf')

    if not args.only_learn:
        if args.target == 'oauth':
            fuzzing_sul = FuzzingSUL(args.op_url, args.rp_url, proxy=args.proxy)
        elif args.target == 'sspoidc':
            fuzzing_sul = FuzzingSSPOIDCSUL(args.op_url, args.rp_url, proxy=args.proxy, fuzz_params=args.fuzz_params, mutation_strategies=args.mutation_strategies)
        elif args.target == 'shiboidc':
            fuzzing_sul = FuzzingShibOIDCSUL(args.op_url, args.rp_url, proxy=args.proxy, fuzz_params=args.fuzz_params, mutation_strategies=args.mutation_strategies)
        
        if args.fuzzing_mode == 'statewise':
            fuzz_model_state_by_state(fuzzing_sul, learned_model, mutations_per_letter=20)
        else:
            fuzz_model(fuzzing_sul, learned_model)