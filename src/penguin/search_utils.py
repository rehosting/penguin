import random
import threading
import math
from collections import defaultdict

class SinglyWeightedSet:
    '''
    This class stores failures and potential solutions. Within each failure we have a set of potential solutions,
    each with its own weight.

    We provide a probabilistic selection mechanism to select one of the failure's solutions based on their weights.
    By default, a failure can also be ignored (Solution: None).

    After observing the result of the selected failure-solution pair, we update the weights for the solutions based
    on the observed result. During observation, we might identify new failures or new solutions.
    These can be added after the initial setup.

    Across multiple runs, this class aims to identify which solutions are the most effective for each failure.

    This class is thread-safe and can be used in a multi-threaded environment.
    '''

    def __init__(self, alpha=0.1):
        # Store failures as a dictionary with potential solutions
        self.failures = {} # (failure_name -> {"solutions": [{"solution": str, "weight": float}]})
        self.past_scores = {} # (failure_name, solution) -> [float] to store past scores for each failure-solution pair
        self.alpha = alpha  # Learning rate for weight updates
        self.max_observed_score = 0  # Track the highest observed score for normalization
        self.min_observed_score = 999999999 # Track the lowest observed score for normalization
        self.lock = threading.Lock()

    def add_failure(self, failure_name, allow_none = True):
        """Add a failure."""
        with self.lock:
            if failure_name not in self.failures:
                self.failures[failure_name] = {
                    "solutions": []
                }
            else:
                raise ValueError(f"Failure '{failure_name}' already exists.")
        if allow_none:
            self.add_solution(failure_name, None)

    def add_solution(self, failure_name, solution, weight=1, exclusive=False):
        """Add a potential solution to an existing failure."""
        assert 0 <= weight <= 1, "Weight must be between 0 and 1"
        with self.lock:
            if failure_name not in self.failures:
                raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")

            # Un-normalize before adding the new solution
            old_len = len(self.failures[failure_name]["solutions"])
            for sol in self.failures[failure_name]["solutions"]:
                sol["weight"] *= old_len

            if solution not in [x["solution"] for x in self.failures[failure_name]["solutions"]]:
                self.failures[failure_name]["solutions"].append({
                    "solution": solution,
                    "weight": weight,
                    "exclusive": exclusive
                })

            for sol in self.failures[failure_name]["solutions"]:
                sol["weight"] /= (old_len + 1)

            # Assert that the sum is 1
            assert math.isclose(sum([x["weight"] for x in self.failures[failure_name]["solutions"]]), 1.0)

    def probabilistic_mitigation_selection(self):
        """Select independent failures to mitigate and pick one of their solutions."""
        selected_failures = []  # (failure_name, solution)
        have_exclusive = False

        # Step 1: For each failure, decide probabilistically if it will be mitigated
        with self.lock:
            for failure_name, failure_data in self.failures.items():
                # If there are no solutions, skip
                if not failure_data["solutions"]:
                    continue

                # Step 2: Select one solution for the chosen failure
                soln = self._select_solution(failure_name, can_be_exclusive=not have_exclusive)
                if soln is not None and soln[1] is not None:
                    selected_failures.append((soln[0], soln[1])) # (failure_name, solution)
                    have_exclusive |= (soln[2] is not None)

        return selected_failures

    def _select_solution(self, failure_name, can_be_exclusive=True):
        """Select a solution for a given failure based on solution weights"""
        # First select all potential solutions. If not can_be_exclusive, filter out
        # exclusive solutions
        solutions = [x for x in self.failures[failure_name]["solutions"] \
                     if (not x["exclusive"] or can_be_exclusive)]
        if solutions:
            solution_weights = [s["weight"] for s in solutions]
            solution_idx = self._weighted_choice(solution_weights)
            selected_solution = solutions[solution_idx]["solution"]
            is_exclusive = solutions[solution_idx]["exclusive"]
            return failure_name, selected_solution, is_exclusive
        return None

    def _weighted_choice(self, weights):
        """Helper function to make a weighted choice from a list of weights"""
        total = sum(weights)
        rand_val = random.uniform(0, total)
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if rand_val < cumulative:
                return i
        return len(weights) - 1  # Fallback to last index

    def report_result(self, selected_failures, final_score):
        """
        Update the weights for solutions based on the observed result (final_score).
        """
        with self.lock:
            # Maintain running statistics for scores to dynamically adapt
            self.min_observed_score = min(self.min_observed_score, final_score)
            self.max_observed_score = max(self.max_observed_score, final_score)
            
            # Normalize score based on observed min and max so far
            if self.max_observed_score > self.min_observed_score:
                normalized_score = (final_score - self.min_observed_score) / (self.max_observed_score - self.min_observed_score)
            else:
                normalized_score = 0.5  # If no range exists, assume neutral

            for failure_name, selected_solution in selected_failures:
                key = (failure_name, selected_solution)

                # Initialize the score history if not present (first run case)
                if key not in self.past_scores:
                    self.past_scores[key] = []
                self.past_scores[key].append(normalized_score)

                # Update the solution weight based on the normalized score
                solution_idx = next(i for i, s in enumerate(self.failures[failure_name]["solutions"])
                                    if s["solution"] == selected_solution)
                solution_data = self.failures[failure_name]["solutions"][solution_idx]
                solution_weight = solution_data["weight"]
                
                # Perform a smoothed Bayesian update with normalized score
                posterior_weight = self._bayesian_update(solution_weight, normalized_score)
                
                # Smooth the weight update by gradually moving towards the posterior weight
                solution_data["weight"] = solution_weight + self.alpha * (posterior_weight - solution_weight)

            # Normalize the weights to ensure they sum to 1
            self._normalize_weights()


    def _normalize_weights(self):
        """
        Ensure that the weights for each failure's solutions sum to 1.
        """
        for failure_name, failure_data in self.failures.items():
            total_weight = sum([sol['weight'] for sol in failure_data["solutions"]])
            if total_weight > 0:
                for sol in failure_data["solutions"]:
                    sol['weight'] /= total_weight
  
    def _expected_score(self, key):
        """Estimate the expected score for the given failure and solution based on past performance."""
        if key not in self.past_scores or not self.past_scores[key]:
            return 0.5  # Default expected score if no history exists

        scores = self.past_scores[key]
        return sum(scores) / len(scores)

    def _bayesian_update(self, prior_weight, score):
        """Perform a Bayesian update of the solution weight."""
        likelihood = score / (1 - score + 1e-6) if score > 0.5 else (1 - score) / (score + 1e-6)
        posterior_weight = prior_weight * likelihood
        posterior_weight = posterior_weight ** 1.5  # This makes updates more aggressive
        return posterior_weight / (posterior_weight + (1 - prior_weight) * (1 - likelihood))


    def __str__(self):
        """Custom string representation to show failures and their solutions"""
        output = ""
        for failure, details in self.failures.items():
            output += f"Failure: {failure}\n"
            for sol in details["solutions"]:
                output += f"  - Solution: {sol['solution']} (Weight: {sol['weight']:.02f}" + (" Exclusive" if sol['exclusive'] else "") + ")\n"
        return output

# Assuming the rest of the script continues from here.

def generate_ground_truth():
    """
    Generate synthetic ground truth for testing. Specify importance for failures
    and impact of solutions.
    """
    return {
        'failure1_important': {
          'f1_soln1': 1,
          'f1_soln2': 10,
          'f1_soln3': 100,
        },
        'failure2_unimportant': {
          'f2_soln1': 1,
          'f2_soln2': 5,
          'f2_soln3': 3,
        },
        'failure3_important': {
          'f3_soln1': 200,
          'f3_soln2': 50,
        }
    }

def create_synthetic_test_data(dws, ground_truth):
    """
    Populate the SinglyWeightedSet instance with synthetic test data.
    """
    # Add failures from the ground truth
    for failure_name, failure_data in ground_truth.items():
        dws.add_failure(failure_name)
        
        # Add possible solutions for each failure with fixed initial weights 
        for solution in failure_data.keys():
            dws.add_solution(failure_name, solution) # Solutions are initially created equally

def simulate_iterations(dws, ground_truth, iterations=100):
    """
    Run multiple iterations to simulate the selection and update process.
    """
    print("Initial weights:")
    print(dws)

    for idx in range(iterations):
        # Select failures and their solutions probabilistically
        selected_failures = dws.probabilistic_mitigation_selection()
        
        # Calculate a synthetic "final score" based on the ground truth.
        # If the selected solution matches the ground truth preferred solution, assign a high score.
        if not selected_failures:
            break

        # Calculate the final score based on the ground truth
        final_score = 0
        for failure, solution in selected_failures:
            final_score += ground_truth[failure][solution]
        
        # Report the result to update weights
        dws.report_result(selected_failures, final_score)
        print(f"\nIteration {idx} selects {selected_failures} with score {final_score}")
        print(dws)

def main():
    # Instantiate the SinglyWeightedSet class
    dws = SinglyWeightedSet()
    
    # Generate synthetic ground truth
    ground_truth = generate_ground_truth()
    
    # Create synthetic test data in the instance
    create_synthetic_test_data(dws, ground_truth)
    
    # Run the synthetic test with multiple iterations
    simulate_iterations(dws, ground_truth, iterations=1000)

if __name__ == "__main__":
    main()
