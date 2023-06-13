import os
import openai
import glob
import tiktoken
import json
from subprocess import check_output
from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
)  # for exponential backoff



# Set up the OpenAI API
openai.api_key = os.getenv("OPENAI_API_KEY")

# Define standard locations for init scripts
STANDARD_LOCATIONS = [
        '/etc/rc*',
        '/etc/init*',
        '/etc/systemd/system/',
        '/usr/local/etc/rc*/']

STANDARD_FILES = [
    '/etc/rc.local'
]


def find_files_in(directory):
    scripts = []
    if os.path.isfile(directory):
        return [directory]
    for item in os.listdir(directory):
        full_path = os.path.join(directory, item)
        if os.path.isfile(full_path):
            scripts.append(full_path)
        elif os.path.isdir(full_path):
            scripts.extend(find_files_in(full_path))
    return scripts

# Function to find all init scripts in standard locations
def find_init_scripts(root_dir):
    scripts = []
    for location in STANDARD_LOCATIONS+STANDARD_FILES:
        path = os.path.abspath(os.path.join(root_dir, '.' + location)) # Note we allow *s in these
        for full_path in glob.glob(path): # So we have to glob them
            scripts.extend(find_files_in(full_path))

    # Check if file is a script
    scripts = [s for s in scripts if b'shell script' in check_output(["file", s])]
    return scripts

# Function to read a script
def read_script(script_path):
    try:
        with open(script_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        return None
    except UnicodeDecodeError as e:
        print(f"Error reading {script_path}: {e}")
        return None

def collect_scripts(paths, root_dir):
    scripts = []
    for path in paths:
        script = read_script(path)
        if script is None or len(script.strip()) == 0:
            continue
        scripts.append((path.replace(root_dir+".", ""), script))
    return scripts

def calculate_cost(scripts):
    ntoks = 0
    encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
    for (path, script) in scripts:
        ntoks += len(encoding.encode(path))
        ntoks += len(encoding.encode(script))

    cost = ntoks * 0.002 / 1000

    if cost < 0.5:
        return True

    print(f"Cost: {cost:.02f} USD")
    res = input("Proceed? [y/n]")
    return res == "y"

def calculate_cost2(s):
    encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
    ntoks = len(encoding.encode(s))

    cost = ntoks * 0.002 / 1000

    if cost < 0.5:
        return True

    print(f"Cost: {cost:.02f} USD")
    res = input("Proceed? [y/n]")
    return res == "y"



PROMPT = 'You are a Linux system administrator assistant. You will be given shell scripts and their path. For each, you will summarize them in JSON labeling binaries they may execute, bash scripts they source, and kernel arguments that may affect their behavior. If there are none, provide an empty list.'

def make_query(script_path, script):
    return f"A linux system has a file at {script_path} with the content shown below. Summarize it.\n{script}"

example_script = """#!/bin/sh
. /etc/cfg
/usr/sbin/ntpdate -b -s -u pool.ntp.org -f /etc/ntp.conf
if [$model_number == "1234"]; then
    /bin/webserver -p 8080
else
    echo "Unexpected model: grep $serialnum ${SERIAL_ROOT}/serials"
fi
"""
example_response = json.dumps({
    "sources": ["/etc/cfg"],
    "binaries": ["/usr/sbin/ntpdate", "/bin/webserver", "grep"],
    "kernel_args": ["model_number", "serialnum", "SERIAL_ROOT"]
}, sort_keys=False)

SOURCED_PROMPT = 'You are a Linux system administrator assistant. You will be given a file that may be sourced by shell scripts. If and only if this file appears to be a valid file that could be sourced by a shell script, you will summarize it into a list of one or more variable and function names that may be set by the file. If the file is invalid or you find no results, return an empty list. Your response must start with ['
def make_source_query(script):
    return f"Provide a list of the values set by sourcing the following linux shell script:\n{script}"

example_source = """
key=thevalue
function foo() {
    echo "Hello, world!"
}
mode=`/bin/get_mode -b`
uid="${model}.${serial}"
"""

example_source_response = '[key, foo, mode, uid]'
#example_source_response = json.dumps({
#        "key": {'type': 'constant', 'value': 'thevalue'},
#        "foo": {'type': 'function'},
#        "mode": {'type': 'command', 'value': '/bin/get_mode -b'},
#        "uid": {'type': 'dynamic', 'value': '${model}.${serial}'}
#    }, sort_keys=False)


ARG_PROMPT = 'You are a Linux system administrator assistant tasked with identifying potential kernel arguments to use when booting an arm or mips firmware image. You will be given a variable name and the output from grepping for file that reference the variable. You will provide a list of potential values the system may expect for the variable. You will build this list based off the grep output and any educated guesses you can make given the variable names and grep results. Values must be alphanmerical with dashes  and without spaces. Your response must start with ['

example_arg = """
File: /etc/run.d/10-foo
3:if [ "$MYVAR" = "banana" ]; then
8:if [ "$MYVAR" = "apple" ]; then
121:    if [ "$MYVAR" = "caps" ]; then

File: /usr/local/bin/helper.sh
9: # Handle when MYVAR is "num" or scroll.
10: # MYVAR is used for something
11: # MYVAR: <string> holds data
18: # MYVAR=<string> - variable
19: MYVAR="pear"
"""
example_arg_response = '["banana", "apple", "caps", "num", "scroll", "pear", "orange"]'

def make_arg_query(arg, grep_matches):
    return f"Provide a list of potential values for the variable {arg} given the following logic that may be examining it:\n{grep_matches}"

            
@retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
def completion_with_backoff(**kwargs):
    return openai.ChatCompletion.create(**kwargs)

# Function to send a script to OpenAI, get the response, and split into tokens
def analyze_script(script_path, script):
    response = completion_with_backoff(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": PROMPT},

            # Example prompt with response
            {"role": "user", "content": make_query('/etc/init.d/example', example_script)},
            {"role": "assistant", "content": example_response},

            # Actual prompt
            {"role": "user", "content": make_query(script_path, script)} 
        ],
        temperature=0,
    )

    result = response.choices[0].message.content
    try:
        decoded = json.loads(result)
    except json.decoder.JSONDecodeError:
        print(f"Failed to decode {script_path}:\n{response}")
        return None
    
    print(script_path, decoded)
    return decoded

def analyze_sourced_script(script_path, script):
    if not os.path.isfile(script_path):
        return None

    # Check filetype
    ftype = check_output(["file", script_path])
    if b"POSIX shell script" not in ftype and b"ASCII text" not in ftype:
        print("Bad filetype:", ftype)
        return None

    response = completion_with_backoff(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": SOURCED_PROMPT},

            # Example prompt with response
            {"role": "user", "content": make_source_query(example_script)},
            {"role": "assistant", "content": example_source_response},

            # Actual prompt
            {"role": "user", "content": make_source_query(script)} 
        ],
        temperature=0,
    )

    result = response.choices[0].message.content
    try:
        # Convert result into a python list from "[key, key2, ...]"
        decoded = result.split("[")[1].split("]")[0].replace('"', '').split(", ")
    except IndexError:
        print(f"Failed to decode analysis of {script_path}:\n{response}")
        return None
    
    return decoded

def find_arg_values(arg, grep_matches):
    '''
    E.g., arg='board' and grep_matches is the output from grepping the FS for 'board'
    We want the AI to give us a list of sane values
    '''

    assert(len(grep_matches) < 100) # Sanity check
    calculate_cost2(str(grep_matches)) # Ensure we don't break the bank

    response = completion_with_backoff(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": ARG_PROMPT},

            # Example prompt with response
            {"role": "user", "content": make_arg_query('example', example_arg)},
            {"role": "assistant", "content": example_arg_response},

            # Actual prompt
            {"role": "user", "content": make_arg_query(arg, grep_matches)} 
        ],
        temperature=0,
    )

    result = response.choices[0].message.content
    try:
        # Convert result into a python list from "[key, key2, ...]"
        decoded = result.split("[")[1].split("]")[0].replace('"', '').split(", ")
    except IndexError:
        print(f"Failed to decode analysis of {arg}, {grep_matches}:\n{response}")
        return None
    
    return decoded

def analyze_fs(root_dir):
    DO_ONE, DO_TWO = (True, True)

    print("\nStage 1: analyze startup scripts")
    if DO_ONE:
        paths = find_init_scripts(root_dir)

        scripts = collect_scripts(paths, root_dir)
        if not calculate_cost(scripts):
            print("Cost not okay - abort")
            return

        # First pass - look at startup scripts, identify what they run, what they source, and what vars they have
        first_pass = {}
        for (path, script) in scripts:
            if response := analyze_script(path, script):
                first_pass[path] = response

        # Cache to disk for debugging
        with open('first_pass.json', 'w') as f:
            json.dump(first_pass, f)
    else: 
        # Load from disk
        with open('first_pass.json', 'r') as f:
            first_pass = json.load(f)

    # Second pass - examine all sourced files to find what they set
    print("\nStage 2: analyze sourced/executed scripts")
    if DO_TWO:
        sourced = {}
        for (path, response) in first_pass.items():
            sources = response['sources'] if 'sources' in response else []

            for bin in response['binaries'] if 'binaries' in response else []:
                # Check if they're shell scripts
                if b'shell script' in check_output(["file", bin]):
                    sources.append(bin)

            for f in sources:
                if f in sourced:
                    continue # Already analyzed

                if "$" in f:
                    continue # Can't handle dynamic includes, for now

                rel_f = os.path.join(root_dir, '.'+f)
                script = read_script(rel_f)

                if not calculate_cost([(rel_f, script)]):
                    print("Cost not okay for {script} - abort")
                    return

                if response := analyze_sourced_script(rel_f, script):
                    sourced[f] = response

        # Cache to disk for debugging
        with open('sourced.json', 'w') as f:
            json.dump(sourced, f)
    else:
        # Load from disk
        with open('sourced.json', 'r') as f:
            sourced = json.load(f)

    # Now we go back through our stage 1 results and drop any vars that are set by sourced files
    for (path, response) in first_pass.items():
        # For each startup script we examined, look at each potential kernel arg
        if 'kernel_args' not in response or 'sources' not in response:
            continue

        for this_var in list(response['kernel_args']):
            # For each potential kernel arg, look at each sourced file to see if it sets it

            for sourced_path in response['sources']:
                if this_var in sourced[sourced_path]:
                    response['kernel_args'].remove(this_var)
                    break

    # Finally, summarize results - what variables do not seem to get set
    print("\nStage 3: Summarize results")
    unique_args = set()
    for (path, response) in first_pass.items():
        n_bins = len(response['binaries']) if 'binaries' in response else 0
        k_args = response['kernel_args'] if 'kernel_args' in response else []
        unique_args.update([x for x in k_args if '/' not in x])

        if len(k_args):
            print(f"Startup script {path} runs {n_bins} binaries. Depends on potential kernel arguments: {k_args}")

    print("\nUnique kernel arguments:")
    print(unique_args)


    # Now let's try finding default values for these arguments
    potential_vals = {} # arg -> [val, val, ...]
    for arg in unique_args:
        # Find all files in the root directory that contain this arg
        last_fname = None
        output = check_output(["grep", "-rIHn", arg, root_dir])        
        matches = {} # fname -> [line, line, ...]

        for line in output.decode('utf-8').split('\n'):
            fname = line.split(':')[0].replace(root_dir, '/')
            line = line[len(fname)+1:]

            if fname not in matches:
                matches[fname] = []
            matches[fname].append(line)

        potential_vals[arg] = find_arg_values(arg, matches)

    print("\nPotential values for kernel arguments:")
    for (arg, vals) in potential_vals.items():
        print(f"{arg}: {vals}")



if __name__ == "__main__":
    from sys import argv
    analyze_fs(argv[1])