#!/usr/bin/env python3
import logging
import inspect
from functools import wraps

class StateAdapter(logging.LoggerAdapter):
    '''
    Logger that includes current a StateTreeFilter's state with each message.

    Usage:
        logger = StateAdapter(logging.getLogger('panda.crawler'), {'state': StateObj})
        logger.info('testing')
    '''
    def process(self, msg, kwargs):
        return '[%s] %s' % (self.extra['state'].state(), msg), kwargs

class StateTreeFilter:
    '''
    Decorators to control when functions are called based on current 'state'.
    A state is a hierarchy - e.g., `main` or `main.sub` or `main.sub.sub2`.
    A function is decorated with a specific state hierarchy. If the
    function state is equal to the current state, it will run.

    By default, states are described as strings delimited by '.' characters
    which are then transformed into lists internally.

    For example:
        current_state  = apple, function_state = orange
        - Function does not run (states do not match)

        current_state  = apple, function_state = apple.eating
        - Function does not run (function labels more specific than current)

        current_state  = apple.eating, function_state = apple
        - Function does run (function labels match current state)

    New states can be pushed, old states can be popped, states can be directly
    set, and old states can be cleared.

    Sub-states can be manipulated if states begin with a '.': I.e., from state
    `apple` you can transition to apple.eating with `push_state('.eating')`.
    From `apple.eating` you can transition to `apple.finished` with
    `change_state('.finished')`
    '''

    def __init__(self, start_state=None, debug=False):
        '''
        States are tracked in a list of lists where the newest state is at the end of the list.
        Within each element, individual sub-states are split apart.
        So self.states looks like [[least_recent, sub_state], [least_recent], ... [most_recent, recent_sub_state]]
        '''
        self.states = []
        self.delimiter = '.'
        self.debug=debug
        if start_state:
            self.change_state(start_state)

    def _parse(self, stateStr):
        '''
        Transform a string state representation to a list by splitting on self.delimiter
        E.g., apple.eating -> [apple, eating]
        E.g., apple -> [apple]
        '''
        return stateStr.split(self.delimiter)
    def _state(self):
        '''
        List representation of current state
        '''
        return self.states[-1] if len(self.states) else []

    def state(self):
        '''
        Delimiter-joined string representing current state
        '''
        return self.delimiter.join(self._state())

    def state_matches(self, target_state):
        '''
        Returns if a state should be run given the current state
        '''

        func_states = self._parse(target_state)
        cur_state_list = self._state()
        for idx, sub_state in enumerate(func_states):
            if idx >= len(cur_state_list):
                # Function more specific than current state
                return False

            if cur_state_list[idx] != sub_state:
                # Mismatch
                return False

        return True


    def push_state(self, new_state):
        '''
        Push the full current state to the state stack and switch to new_state.

        If new_state begins with a '.' treat it as a sub-state of current state.
        E.g., from `apple` running `change_state('.eating')` would go to
        `apple.eating`.

        Note current state is already stored as last element in self.states so
        we just need to append new_state
        '''

        prefix = []
        if new_state.startswith('.') and len(self.states):
            prefix = self.states[-1]
            new_state = new_state[1:]
        state_to_push = prefix + self._parse(new_state)
        self.states.append(state_to_push)

    def pop_state(self):
        '''
        Drop the full current state from the state stack and restore the prior state.

        Note we accomplish this by just dropping the last element in self.states

        Raises IndexError if no states remain to pop
        '''
        if len(self.states) == 1:
            raise IndexError('No remaining states')

        self.states = self.states[:-1]

    def change_state(self, new_state):
        '''
        Directly change the full current state without storing prior value

        If new state begins with a ., change at the sub-state level
        E.g.,: from `apple.eating` running `change_state('.finished) moves to
        `apple.finished`

        Note we accomplish this by dropping the last element in self.states
        (if one is present) and appending the new state.
        '''
        if self.debug:
            old_state = self.state()

        prefix = []
        if new_state.startswith('.') and len(self.states):
            prefix = self.states[-1]
            if len(prefix) > 1:
                prefix = prefix[:-1]  # Drop last element
            new_state = new_state[1:]

        if len(self.states):
            self.states = self.states[:-1] + [prefix+self._parse(new_state)]
        else:
            self.states = [prefix+self._parse(new_state)]

        if self.debug:
            frame = inspect.stack()[1]
            print(f"STATE CHANGE [{old_state} -> {self.state()}] in {frame.function} at {frame.filename}:{frame.lineno}")

    def state_filter(self, mode, default_ret=None):
        '''
        Run a function if it's decorated mode matches our current mode.
        If function shouldn't run, it will return None or `default_ret`
        '''
        def __state_filter(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.state_matches(mode):
                    # Mode matches - run it!
                    return func(*args, **kwargs)
                elif default_ret is not None:
                    return default_ret
            return wrapper
        return __state_filter

if __name__ == "__main__":
    S = StateTreeFilter(start_state='apple')

    @S.state_filter('apple')
    def apple():
        print("State 1/State 3 Apples!")
        if S.state() == 'apple':
            S.push_state('.eat') # Only push on stage 1

    @S.state_filter('apple.eat')
    def eat_apple():
        print("State 2: Eating apples")
        S.change_state('.finished')

    @S.state_filter('apple.finished')
    def finish_apple():
        print("State 3: Finished apples")
        S.change_state('orange')

    @S.state_filter('orange')
    def orange():
        print("State 4: Oranges")
        S.change_state('quit')

    @S.state_filter('quit')
    def quit():
        print("State 5: Success")
        from sys import exit
        exit(0)

    funcs = [quit, eat_apple, apple, finish_apple, orange]

    for x in range(10):
        start_state = S.state()
        print(f"---------- LOOP FROM {start_state} ----------")
        for f in funcs:
            if S.state() != start_state:
                # Just to simplify example, otherwise state
                # changes within each round of running fns
                break
            f()

    assert 0, "State machine should have exited previously"
