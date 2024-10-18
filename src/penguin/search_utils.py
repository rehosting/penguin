import random
import threading
from collections import defaultdict
import numpy as np

class MABWeightedSet:
    '''
    This class stores failures and potential solutions. Within each failure we have a set of potential solutions,
    each with its own weight, and we model each solution using Thompson Sampling with a Beta distribution.

    We provide a probabilistic selection mechanism to select one of the failure's solutions based on Thompson Sampling.
    After observing the result of the selected failure-solution pair, we update the Beta distributions for the solutions 
    based on the observed result.

    This class is thread-safe and can be used in a multi-threaded environment.
    '''

    def __init__(self, alpha=5, beta=10):
        # Store failures as a dictionary with potential solutions
        self.failures = {}  # (failure_name -> {"solutions": [{"solution": str, "alpha": float, "beta": float}]})
        self.alpha_init = alpha  # Initial alpha value for the Beta distribution
        self.beta_init = beta    # Initial beta value for the Beta distribution
        self.observed_scores = []  # Track all observed scores
        self.selections = []

        self.lock = threading.Lock()

    def add_failure(self, failure_name, allow_none=True):
        """Add a failure."""
        with self.lock:
            if failure_name not in self.failures:
                self.failures[failure_name] = {"solutions": []}
            else:
                raise ValueError(f"Failure '{failure_name}' already exists.")
        
        if allow_none:
            self.add_solution(failure_name, None)

    def add_solution(self, failure_name, solution, exclusive=False):
        """Add a potential solution to an existing failure."""
        with self.lock:
            if failure_name not in self.failures:
                raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")

            if solution not in [x["solution"] for x in self.failures[failure_name]["solutions"]]:
                self.failures[failure_name]["solutions"].append({
                    "solution": solution,
                    "alpha": self.alpha_init,  # Beta distribution alpha (success count)
                    "beta": self.beta_init,    # Beta distribution beta (failure count)
                    "exclusive": exclusive
                })

    def probabilistic_mitigation_selection(self):
        """Select independent failures to mitigate and pick one of their solutions."""
        for _ in range(1000):  # Limiting to 100 tries for fairness
            selected_failures = []  # (failure_name, solution)
            have_exclusive = False
            epsilon = 0.05  # 5% chance to explore at random

            with self.lock:
                for failure_name, failure_data in self.failures.items():
                    if not failure_data["solutions"]:
                        continue

                    # With probability epsilon, explore a random solution
                    soln = None
                    if random.random() < epsilon:
                        soln = self._select_solution_random(failure_name, can_be_exclusive=not have_exclusive) # returns (solution, exclusive)

                    if not soln:
                        # If not randomly picking (or if random failed)
                        # Select one solution for the chosen failure using Thompson Sampling
                        soln = self._select_solution(failure_name, can_be_exclusive=not have_exclusive) # returns (solution, exclusive)

                    if soln is not None and soln[0] is not None:
                        selected_failures.append((failure_name, soln[0]))  # (failure_name, solution)
                        have_exclusive |= (soln[1] is not None)

                if selected_failures not in self.selections:
                    self.selections.append(selected_failures)
                    return selected_failures

    def upper_confidence_bound(self, alpha, beta, n_total, n_solution):
        """Calculate the UCB for a given solution."""
        success_rate = alpha / (alpha + beta)
        exploration_term = np.sqrt(2 * np.log(n_total + 1) / (n_solution + 1))  # Exploration incentive
        return success_rate + exploration_term

    def _select_solution_random(self, failure_name, can_be_exclusive=True):
        solutions = [x for x in self.failures[failure_name]["solutions"] \
                     if not x["exclusive"] or can_be_exclusive]
        if solutions:
            soln = random.choice(solutions)
            if soln and soln["solution"]:
                return soln["solution"], soln["exclusive"]
        return None

    def _select_solution(self, failure_name, can_be_exclusive=True):
        """Select a solution for a given failure using Thompson Sampling."""
        solutions = [x for x in self.failures[failure_name]["solutions"] \
                     if not x["exclusive"] or can_be_exclusive]

        if solutions:
            # Use Thompson Sampling by sampling from Beta(alpha, beta) for each solution
            sampled_weights = [np.random.beta(sol["alpha"], sol["beta"]) for sol in solutions]
            solution_idx = sampled_weights.index(max(sampled_weights))  # Choose the solution with the highest sample
            selected_solution = solutions[solution_idx]["solution"]
            is_exclusive = solutions[solution_idx]["exclusive"]
            return selected_solution, is_exclusive
        return None

    def report_result(self, selected_failures, final_score):
        """
        Update the Beta distribution for the selected solution based on the observed result.
        """
        with self.lock:
            self.observed_scores.append(final_score)
            avg_score = sum(self.observed_scores) / len(self.observed_scores)

            for failure_name, selected_solution in selected_failures:
                solution_idx = next(i for i, s in enumerate(self.failures[failure_name]["solutions"])
                                    if s["solution"] == selected_solution)
                solution_data = self.failures[failure_name]["solutions"][solution_idx]

                # Update distributions based on final score
                decay_factor = 0.9  # Introduce a decay factor
                weight = decay_factor * self.weighted_likelihood(final_score, avg_score)

                if final_score > avg_score:  # Success case
                    solution_data["alpha"] += weight  # Weighted update
                else:  # Failure case
                    solution_data["beta"] += weight  # Weighted update

    def weighted_likelihood(self, final_score, avg_score):
        """Calculate a weighted likelihood for updating based on score deviation."""
        weight = abs(final_score - avg_score)  # More deviation = more weight
        return min(1.0, weight)  # Cap weight at 1.0 to avoid excessive adjustments

    def __str__(self):
        """Custom string representation to show failures and their solutions"""
        output = ""
        for failure, details in self.failures.items():
            output += f"Failure: {failure}\n"
            for sol in details["solutions"]:
                output += f"  - Solution: {sol['solution']} (Alpha: {sol['alpha']:.02f}, Beta: {sol['beta']:.02f}" + (" Exclusive" if sol['exclusive'] else "") + ")\n"
        return output

if __name__ == "__main__":
    # Unit testing
    def generate_ground_truth():
        """
        Generate synthetic ground truth for testing. Specify importance for failures
        and impact of solutions.
        """
        ground_truth = {
            'failure1': {
            'f1_soln1': random.randint(1, 1000),
            'f1_soln2': random.randint(1, 10000),
            'f1_soln3': random.randint(1, 500),
            },
            'failure2': {
            'f2_soln1': random.randint(1, 10),
            'f2_soln2': random.randint(1, 10),
            'f2_soln3': random.randint(1, 10),
            },
            'failure3': {
            'f3_soln1': random.randint(1, 100),
            'f3_soln2': random.randint(1, 100)
            }
        }

        for f in ground_truth.keys():
            ground_truth[f][None] = 0

        return ground_truth

    def create_synthetic_test_data(mab, ground_truth):
        """
        Populate the MABWeightedSet instance with synthetic test data.
        """
        # Add failures from the ground truth
        for failure_name, failure_data in ground_truth.items():
            mab.add_failure(failure_name)
            
            # Add possible solutions for each failure with fixed initial weights 
            for solution in failure_data.keys():
                mab.add_solution(failure_name, solution)  # Solutions are initially equal

    def simulate_iterations(mab, ground_truth, iterations=100):
        """
        Run multiple iterations to simulate the selection and update process.
        """
        for idx in range(iterations):
            # Select failures and their solutions probabilistically
            selected_failures = mab.probabilistic_mitigation_selection()
            
            # Calculate a synthetic "final score" based on the ground truth.
            # If the selected solution matches the ground truth preferred solution, assign a high score.
            if not selected_failures:
                break

            # Calculate the final score based on the ground truth
            final_score = 0
            for failure, solution in selected_failures:
                final_score += ground_truth[failure][solution]

            final_score /= sum(len(v) for v in ground_truth.values())  # Normalize score between 0 and 1

            # Report the result to update the Beta distributions
            mab.report_result(selected_failures, final_score)
            print(f"Iteration {idx} selects  " + ", ".join([f"{k}={v}" for (k, v) in selected_failures]) + f" with score {final_score:.02f}")

    def main():
        # Instantiate the MABWeightedSet class
        mab = MABWeightedSet()
        
        # Generate synthetic ground truth
        ground_truth = generate_ground_truth()
        
        # Create synthetic test data in the instance
        create_synthetic_test_data(mab, ground_truth)
        
        # Run the synthetic test with multiple iterations
        simulate_iterations(mab, ground_truth, iterations=500)
        
        # Print the final state of the failures and solutions
        print(mab)

        best = {} # failure -> best
        for fail, solns in ground_truth.items():
            best[fail] = max(solns, key=lambda x: solns[x])
            print(f"Failure: {fail}")
            for soln, value in solns.items():
                print(f"  - {soln}: {value}")

        # Get best results
        for failure, failure_data in mab.failures.items():
            best_soln = max(failure_data["solutions"], key=lambda x: x["alpha"] / (x["alpha"] + x["beta"]))
            delta = abs(ground_truth[failure][best[failure]] - ground_truth[failure][best_soln["solution"]])
            if best_soln["solution"] == best[failure] or delta == 0:
                print(f"FOUND BEST for {failure}: {best[failure]}: weight {ground_truth[failure][best[failure]]}")
            else:
                print(f"MISMATCH for {failure}: {best[failure]} != {best_soln['solution']}: delta = {delta}")

    main()