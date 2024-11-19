import random
import threading
import numpy as np
from .graphs import Failure, Mitigation
from .utils import get_mitigation_providers
from typing import List
import os
from copy import deepcopy


class MABWeightedSet:
    '''
    This class stores failures and potential solutions. Within each failure we have a set of potential solutions,
    each with its own weight, and we model each solution using Thompson Sampling with a Beta distribution.

    We provide a probabilistic selection mechanism to select one of the failure's solutions based on Thompson Sampling.
    After observing the result of the selected failure-solution pair, we update the Beta distributions for the solutions
    based on the observed result.

    This class is thread-safe and can be used in a multi-threaded environment.
    '''

    def __init__(self, alpha=5, beta=5):
        # Store failures as a dictionary with potential solutions
        self.failures = {}  # (failure_name -> {"solutions": [{"solution": str, "alpha": float, "beta": float}]})
        self.alpha_init = alpha  # Initial alpha value for the Beta distribution
        self.beta_init = beta    # Initial beta value for the Beta distribution
        self.observed_scores = []  # Track all observed scores
        self.selections = []
        self.learning_queue = {}  # failure name -> {config: config, exclusive: provider}
        self.already_learned = set()

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

    def queue_learning(self, failure_name, mitigation, config, exclusive):
        """
        On a run we observed a failure that produced an exclusive mitigation - in other words, an analysis
        has requested we do a special (and expensive) run just so we can learn more about potential solutions to the failure.
        For now we'll do it ASAP if it's a new mitigation, otherwise we'll ignore
        """
        with self.lock:
            if failure_name in self.already_learned or failure_name in self.learning_queue:
                # Already learned or queued
                return

            self.learning_queue[failure_name] = {
                "patches": deepcopy(config['patches']) + [mitigation],
                "exclusive": exclusive,
            }

    def add_solution(self, failure_name, solution, exclusive=None):
        """Add a potential solution to an existing failure."""
        with self.lock:
            if failure_name not in self.failures:
                raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")

            if exclusive is not None and not isinstance(exclusive, str):
                raise ValueError(f"Exclusive must be None or the name of a failure, not {exclusive} in {failure_name} -> {solution}")

            if solution not in [x["solution"] for x in self.failures[failure_name]["solutions"]]:
                self.failures[failure_name]["solutions"].append({
                    "solution": solution,
                    "alpha": self.alpha_init,  # Beta distribution alpha (success count)
                    "beta": self.beta_init,    # Beta distribution beta (failure count)
                    "exclusive": exclusive
                })

    def probabilistic_mitigation_selection(self):
        """Select independent failures to mitigate and pick one of their solutions."""
        with self.lock:
            # If we have any entries in self.learning_queue, we'll process them first
            if len(self.learning_queue.keys()):
                # Need to return a list with an exact set of patches to run in [(failure_name, patch), ]
                failure_name = next(iter(self.learning_queue.keys()))
                self.already_learned.add(failure_name)
                soln = self.learning_queue.pop(failure_name)

                print("Selected exclusive configuration:", failure_name, soln['patches'][-1])

                return [(f"exclusive_{failure_name}_{soln['exclusive']}", patch) for patch in soln['patches']]

        for _ in range(1000):  # Limiting to 100 tries for fairness
            selected_failures = []  # (failure_name, solution)
            have_exclusive = False
            epsilon = 0.05  # 5% chance to explore at random within each failure

            with self.lock:
                # TODO: should we order failures randomly here to ensure we don't bias towards early exclusive choices?
                for failure_name, failure_data in self.failures.items():
                    # print("Selecting solution for:", failure_name)
                    if not failure_data["solutions"]:
                        print("\tNo solutions available for:", failure_name)
                        continue

                    # With probability epsilon, explore a random solution
                    soln = None
                    if random.random() < epsilon:
                        # print("\tSelecting random solution for:", failure_name)
                        soln = self._select_solution_random(failure_name, can_be_exclusive=not have_exclusive)  # returns (solution, exclusive)

                    if not soln:
                        # print("\tSelecting Thompson Sampled solution for:", failure_name)
                        # If not randomly picking (or if random failed)
                        # Select one solution for the chosen failure using Thompson Sampling
                        soln = self._select_solution(failure_name, can_be_exclusive=not have_exclusive)  # returns (solution, exclusive)

                    if soln is not None and soln[0] is not None:
                        # print("\tSelected solution:", soln[0])
                        # print("\tExclusive:", soln[1])
                        selected_failures.append((failure_name, soln[0]))  # (failure_name, solution)
                        assert (soln[1] is not False)  # Sanity check - was previously bool but is not Optional[str]

                        have_exclusive |= (soln[1] is not None)

                if selected_failures not in self.selections:
                    self.selections.append(selected_failures)
                    return selected_failures
            print("Failed to find any solutions?")

    def _select_solution_random(self, failure_name, can_be_exclusive=True):
        solutions = [x for x in self.failures[failure_name]["solutions"]
                     if not x["exclusive"] or can_be_exclusive]

        # print("\tPotential solutions for", failure_name, ":")
        # for s in solutions:
        #    print("\t\t", s)

        if solutions:
            soln = random.choice(solutions)
            if soln and soln["solution"]:
                return soln["solution"], soln["exclusive"]
        return None

    def _select_solution(self, failure_name, can_be_exclusive=True):
        """Select a solution for a given failure using Thompson Sampling."""
        solutions = [x for x in self.failures[failure_name]["solutions"]
                     if not x["exclusive"] or can_be_exclusive]
        # print("\tPotential solutions for", failure_name, ":")
        # for s in solutions:
        #    print("\t", s)

        if solutions:
            # Use Thompson Sampling by sampling from Beta(alpha, beta) for each solution
            sampled_weights = [np.random.beta(sol["alpha"], sol["beta"]) for sol in solutions]
            solution_idx = sampled_weights.index(max(sampled_weights))  # Choose the solution with the highest sample
            selected_solution = solutions[solution_idx]["solution"]
            is_exclusive = solutions[solution_idx]["exclusive"]
            return selected_solution, is_exclusive

        # print("No valid solutions found for", failure_name)
        # print(self.failures[failure_name]["solutions"])
        # print()
        return None

    def report_result(self, selected_failures, final_score):
        """
        Update the Beta distribution for the selected solution based on the observed result.
        """

        # Before we update the average score or our alphas/betas, we need to see if this is
        # the result of an exclusive run - it will be if every failure_name starts with "exclusive_"
        if all(failure_name.startswith("exclusive_") for failure_name, _ in selected_failures):
            # We're in a learning mode - just ignore the result
            print("\tIgnoring run, was exclusive")
            return

        with self.lock:
            self.observed_scores.append(final_score)
            avg_score = sum(self.observed_scores) / len(self.observed_scores)

            for failure_name, selected_solution in selected_failures:
                if failure_name.startswith("exclusive_"):
                    raise ValueError

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


class ConfigSearch:
    """
    This class contains logic that would be shared across various configuration search algorithms.
    """

    def __init__(self):
        # We expect children to set up their own logger
        pass

    def find_mitigations(self, failure: Failure, config) -> List[Mitigation]:
        results = []
        # Lookup the plugin that can handle this failure
        analysis = get_mitigation_providers(config)[failure.type]
        for m in analysis.get_potential_mitigations(config, failure) or []:
            if not isinstance(m, Mitigation):
                raise TypeError(
                    f"Plugin {analysis.ANALYSIS_TYPE} returned a non-Mitigation object {m}"
                )
            results.append(m)
        return results

    def analyze_failures(self, config, run_dir, exclusive=None):
        """
        After we run a configuration, do our post-run analysis of failures.
        Run each PyPlugin that has a PenguinAnalysis implemented. Ask each to
        identify failures.
        """

        fails = []  # (id, type, {data})
        output_dir = os.path.join(run_dir, "output")

        mitigation_providers = get_mitigation_providers(config)

        # For an exclusive config, only query the exclusive provider
        if exclusive is not None:
            if exclusive not in mitigation_providers:
                raise ValueError(
                    f"Cannot use exclusive {exclusive} as it's not a mitigation provider"
                )
            mitigation_providers = {
                exclusive: mitigation_providers[exclusive]
            }

        for plugin_name, analysis in mitigation_providers.items():
            try:
                failures = analysis.parse_failures(output_dir)
            except Exception as e:
                self.logger.error(e)
                raise e

            for failure in failures or []:
                if not isinstance(failure, Failure):
                    raise TypeError(
                        f"Plugin {plugin_name} returned a non-Failure object {failure}"
                    )
                fails.append(failure)

        # We might have duplicate failures, but that's okay, caller will dedup?
        return fails


if __name__ == "__main__":
    # Unit testing
    def generate_ground_truth(N=5, M=5, min_weight=-100, max_weight=100, scale=1.2):
        """
        Generate synthetic ground truth for testing. Create N distinct failures with between 1 and M solutions each.
        Each solution has a weight from scale**(min_weight to max_weight).
        """
        ground_truth = {}

        # Add N failures with a random number 2, M solutions with random weights
        N = 5
        M = 5
        for i in range(N):
            ground_truth[f"failure{i}"] = {f"solution{j}": round((scale)**random.randint(min_weight, max_weight), 2) for j in range(random.randint(1, M))}

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
        print("========= RESULTS ========")
        print(mab)

        best = {}  # failure -> best
        for fail, solns in ground_truth.items():
            best[fail] = max(solns, key=lambda x: solns[x])
            print(f"Failure: {fail}")
            for soln, value in solns.items():
                print(f"  - {soln}: {value}")

        # Get best results
        # If we had picked the best value for each failure, what would our total score be?
        best_weight = sum(ground_truth[failure][best[failure]] for failure in ground_truth)

        found_weight = 0
        for failure, failure_data in mab.failures.items():
            # Select the best solution from our MAB solution by alpha / (alpha + beta). Could also just use alpha?
            best_soln = max(failure_data["solutions"], key=lambda x: x["alpha"] / (x["alpha"] + x["beta"]))
            found_weight += ground_truth[failure][best_soln["solution"]]
            print(f"For {failure} best identified solution is {best_soln['solution']}")

        print(f"Best possible score: {best_weight}")
        print(f"MAB solution: {found_weight}")

        percent_diff = (found_weight - best_weight) / best_weight
        print(f"% difference: {100 * percent_diff:.02f}%")

        if percent_diff > -0.1:
            print("PASS")
        else:
            print("FAIL")

    main()
