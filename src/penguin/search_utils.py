import random
import threading
import math

class DoublyWeightedSet:
    '''
    This class stores failures and potential solutions. Within each failure we have a set of potential solutions,
    each with its own weight. The failures themselves also have a weight to measure how important they are.

    A user can specify that a given failure or solution _must_ be selected every time (e.g., for critical components
    with known solutions).

    We provide a probabilistic selection mechanism to select a failure and one of its solutions based on their weights.

    After observing the result of the selected failure-solution pair, we update the weights for both the failures and
    solutions based on the observed result. During observation, we might identify new failures or new solutions.
    These can be added after the initial setup.

    Across multiple runs, this class aims to identify which failures are important and which solutions are the most
    effective for each failure.

    This class is thread-safe and can be used in a multi-threaded environment.
    '''

    def __init__(self):
        # Store failures as a dictionary with weights and their potential solutions
        self.failures = {} # (failure_name -> {"weight": float, "solutions": [{"solution": str, "weight": float}]})
        self.past_scores = {} # (failure_name, solution) -> [float] to store past scores for each failure-solution pair
        self.alpha = 0.01  # Learning rate for weight updates
        self.lock = threading.Lock()

    def add_failure(self, failure_name, weight=0.5, always_select=False):
        """Add a failure with a specific weight (default 0.5) and a flag to always select it."""
        with self.lock:
            if failure_name not in self.failures:
                self.failures[failure_name] = {
                    "weight": weight,
                    "solutions": [],
                    "always_select": always_select  # Mark failures that should always be selected
                }
            else:
                raise ValueError(f"Failure '{failure_name}' already exists.")

    def add_solution(self, failure_name, solution, weight=0.5, exclusive=False, always_select=False):
        """Add a potential solution to an existing failure, with an option to always select."""
        with self.lock:
            if failure_name in self.failures:
                if solution not in [x["solution"] for x in self.failures[failure_name]["solutions"]]:
                    self.failures[failure_name]["solutions"].append({
                        "solution": solution,
                        "weight": weight,
                        "exclusive": exclusive,
                        "always_select": always_select  # Mark solution that should always be applied
                    })
            else:
                raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")


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

                # If the failure or solution is marked as always_select, skip the probabilistic check
                if failure_data.get("always_select", False):
                    selected_solution = failure_data["solutions"][0]["solution"]
                    selected_failures.append((failure_name, selected_solution))
                    continue

                failure_weight = failure_data["weight"]
                if random.random() <= failure_weight:
                    # Step 2: Select one solution for the chosen failure
                    soln = self._select_solution(failure_name, can_be_exclusive=not have_exclusive)
                    if soln[1] is not None:
                        selected_failures.append((soln[0], soln[1]))
                        have_exclusive |= (soln[2] is not None)

        return selected_failures

    def _select_solution(self, failure_name, can_be_exclusive=True):
        """Select a solution for a given failure based on solution weights"""
        # First select all potential solutions. If not can_be_exclusive, filter out
        # exclusive solutions
        solutions = [x for x in self.failures[failure_name]["solutions"] \
                     if not x["exclusive"] or can_be_exclusive]
        if solutions:
            solution_weights = [s["weight"] for s in solutions]
            solution_idx = self._weighted_choice(solution_weights)
            selected_solution = solutions[solution_idx]["solution"]
            is_exclusive = solutions[solution_idx]["exclusive"]
            return failure_name, selected_solution, is_exclusive
        else:
            return failure_name, None, False

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
        Update the weights for both failures and solutions based on the observed result (final_score).
        """
        with self.lock:
            for failure_name, selected_solution in selected_failures:
                # Initialize history of scores for this failure-solution pair if not present
                key = (failure_name, selected_solution)

                # Initialize the score history if not present (first run case)
                if key not in self.past_scores:
                    self.past_scores[key] = []
                    expected_score = final_score  # Default to the current score for first run
                    normalized_score = 0.5  # Neutral midpoint for the first run
                else:
                    self.past_scores[key].append(final_score)
                    normalized_score = self._normalize_score(key)
                    expected_score = self._expected_score(key)

                # Append the new score to this failure-solution's history
                self.past_scores[key].append(final_score)

                # Normalize score based on the history of past scores for this pair
                normalized_score = self._normalize_score(key)

                # Update the failure and solution weights based on the normalized score
                failure_data = self.failures[failure_name]
                failure_weight = failure_data["weight"]
                expected_score = self._expected_score(key)

                error_term = normalized_score - expected_score
                new_failure_weight = failure_weight + self.alpha * error_term
                failure_data["weight"] = max(0.0, min(1.0, new_failure_weight))  # Keep within [0, 1]

                # Update the solution weight (with Bayesian-like updating)
                solution_idx = next(i for i, s in enumerate(failure_data["solutions"])
                                    if s["solution"] == selected_solution)
                solution_data = failure_data["solutions"][solution_idx]
                solution_weight = solution_data["weight"]
                posterior_weight = self._bayesian_update(solution_weight, normalized_score)
                solution_data["weight"] = posterior_weight

    def _normalize_score(self, key):
        """Normalize the score based on the history of past scores for the given key (failure, solution)."""
        if key not in self.past_scores or not self.past_scores[key]:
            return 0.5  # Default score if no history exists

        scores = self.past_scores[key]

        # Compute the mean and range
        mean_score = sum(scores) / len(scores)
        score_range = max(scores) - min(scores) if len(scores) > 1 else 1

        # Normalize the most recent score
        normalized_score = (scores[-1] - mean_score) / score_range

        # Ensure normalization doesn't zero out or produce extreme values
        return max(0.0, min(1.0, normalized_score))

    def _expected_score(self, key):
        """Estimate the expected score for the given failure and solution based on past performance."""
        if key not in self.past_scores or not self.past_scores[key]:
            return 0.5  # Default expected score if no history exists

        scores = self.past_scores[key]
        if not isinstance(scores, list):  # Type check to ensure correct type
            raise TypeError(f"Expected list for past_scores[{key}], got {type(scores)}")

        return sum(scores) / len(scores)

    def _bayesian_update(self, prior_weight, score):
        """Perform a Bayesian update of the solution weight."""
        likelihood = math.exp(-abs(score - 0.5))  # A simple likelihood function
        posterior_weight = prior_weight * likelihood
        return posterior_weight / (posterior_weight + (1 - prior_weight) * (1 - likelihood))

    def __str__(self):
        """Custom string representation to show failures and their solutions"""
        output = ""
        for failure, details in self.failures.items():
            output += f"Failure: {failure} (Weight: {details['weight']})\n"
            for sol in details["solutions"]:
                output += f"  - Solution: {sol['solution']} (Weight: {sol['weight']}, Exclusive: {sol['exclusive']})\n"
        return output