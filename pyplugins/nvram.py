import itertools
import string
import tarfile
from io import BytesIO

import yaml
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from pandare import PyPlugin

console_path = "console.log"


def extract_buffers_after_keys(binary_data, keys, buffer_size=100):
    buffers = {}
    for key in keys:
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        start_indices = [
            i for i in range(len(binary_data)) if binary_data.startswith(key_bytes, i)
        ]
        if len(start_indices) == 0:
            continue
        buffers[key] = [
            binary_data[start + len(key_bytes): start + len(key_bytes) + buffer_size]
            for start in start_indices
        ]
    return buffers


def analyze_buffer_frequencies(buffers, buffer_size=100):
    frequency_table = [{} for _ in range(buffer_size)]
    for buffer_list in buffers.values():
        for buffer in buffer_list:
            for i in range(min(len(buffer), buffer_size)):
                byte = buffer[i: i + 1]
                frequency_table[i][byte] = frequency_table[i].get(byte, 0) + 1

    return frequency_table


def find_common_nonalphanum_bytes(frequency_table, threshold=0.4):
    common_bytes = set()
    for position_frequencies in frequency_table:
        total_buffers = sum(position_frequencies.values())
        for byte, count in position_frequencies.items():
            if count / total_buffers >= threshold and not byte.decode() in (
                string.ascii_letters + string.digits
            ):
                common_bytes.add(byte)
    return common_bytes


def infer_delimiters(common_bytes, max_sequence_length=2):
    delimiters = set()
    for length in range(1, max_sequence_length + 1):
        for sequence in itertools.product(common_bytes, repeat=length):
            delimiters.add(b"".join(sequence))
    return delimiters


def validate_extraction(binary_data, keys, kv_delimiter, pair_delimiter):
    kv_pairs = {}
    for key in keys:
        search_pattern = (
            key.encode("utf-8") if isinstance(key, str) else key
        ) + kv_delimiter
        start = 0
        while True:
            start = binary_data.find(search_pattern, start)
            if start == -1:
                break
            value_start = start + len(search_pattern)
            value_end = binary_data.find(pair_delimiter, value_start)
            if value_end == -1:
                value_end = len(binary_data)
            value = binary_data[value_start:value_end]
            kv_pairs[key] = value.decode("utf-8", errors="ignore")
            start = value_end + len(pair_delimiter)
    return kv_pairs


def count_correct_key_value_pairs(extracted_values, keys):
    correct_values = 0
    for key in keys:
        if key in extracted_values:
            correct_values += 100000 - len(extracted_values[key])
    return correct_values


def find_extended_key_range(binary_data, keys, kv_delimiter, extension=100):
    first_key_pos = len(binary_data)
    last_key_pos = 0

    for key in keys:
        key_sequence = (
            key.encode("utf-8") if isinstance(key, str) else key
        ) + kv_delimiter
        positions = [
            i
            for i in range(len(binary_data))
            if binary_data.startswith(key_sequence, i)
        ]
        if positions:
            first_key_pos = min(first_key_pos, min(positions))
            last_key_pos = max(last_key_pos, max(positions) + len(key_sequence))

    # Extend the range
    start = max(0, first_key_pos - extension)
    end = min(len(binary_data), last_key_pos + extension)
    return start, end


def extract_keys_from_range(
    binary_data, start, end, kv_delimiter, pair_delimiter, known_keys
):
    additional_keys = set()
    key_value_data = binary_data[start:end]
    current_pos = 0
    new_kvs = {}

    while current_pos < len(key_value_data):
        # Find the next occurrence of the key-value delimiter
        kv_delim_pos = key_value_data.find(kv_delimiter, current_pos)
        pair_delim_pos = key_value_data.find(pair_delimiter, current_pos)

        # Check for the end of search
        if kv_delim_pos == -1 and pair_delim_pos == -1:
            break

        next_pos = None
        # Distinguish between key-value delimiter and pair delimiter
        if kv_delim_pos != -1 and (
            kv_delim_pos < pair_delim_pos or pair_delim_pos == -1
        ):
            next_pos = kv_delim_pos + len(kv_delimiter)
        elif pair_delim_pos != -1:
            next_pos = pair_delim_pos + len(pair_delimiter)

        # Extract the potential key-value pair
        potential_key_val = key_value_data[current_pos:next_pos].strip()
        if kv_delimiter in potential_key_val:
            key, val = potential_key_val.split(kv_delimiter, 1)
            key = key.decode("utf-8", errors="ignore")
            if key.isalnum() and key not in known_keys:
                additional_keys.add(key)
                new_kvs[key] = val.decode("utf-8", errors="ignore")

        # Update the current position
        current_pos = next_pos

    return new_kvs


def test_delimiter_combinations(binary_data, potential_delimiters, keys):
    best_kv_delimiter = None
    best_pair_delimiter = None
    best_extraction = None
    max_correct_values = 0

    for kv_delimiter in potential_delimiters:
        for pair_delimiter in potential_delimiters:
            extracted_values = validate_extraction(
                binary_data, keys, kv_delimiter, pair_delimiter
            )
            if not len(extracted_values):
                continue
            correct_values = count_correct_key_value_pairs(extracted_values, keys)
            if correct_values >= max_correct_values:
                if correct_values == max_correct_values:
                    # Same number of correct values. Prefer the longer delimiters
                    if len(kv_delimiter) + len(pair_delimiter) < len(
                        best_kv_delimiter
                    ) + len(best_pair_delimiter):
                        continue

                max_correct_values = correct_values
                best_kv_delimiter = kv_delimiter
                best_pair_delimiter = pair_delimiter
                best_extraction = extracted_values

    # Experimental: extend the range of the search to find additional keys
    # start, end = find_extended_key_range(binary_data, keys, best_kv_delimiter)
    # new_keys = extract_keys_from_range(binary_data, start, end, best_kv_delimiter, best_pair_delimiter, keys)

    return best_kv_delimiter, best_pair_delimiter, best_extraction


def keyfinder(binary_data, keys):
    """
    given binary data with some keys, try finding
    the best inner and intra key-value delimiter
    return these and the extraction
    """

    # num_keys = [k for k in keys if re.match(r'^[0-9]+$', k.decode())]
    # For every numeric key we see try also swapping numbers for a %d version. use regex
    # to find all numeric keys and then replace each number with "%d"
    # num_keys_sub = [re.sub(r'[0-9]+', r'%d', k.decode()).encode() for k in num_keys if re.match(r'^[0-9]+$', k.decode())]

    buffers = extract_buffers_after_keys(binary_data, keys)
    frequency_table = analyze_buffer_frequencies(buffers)
    common_bytes = find_common_nonalphanum_bytes(frequency_table)
    potential_delimiters = infer_delimiters(common_bytes)
    best_kv_delimiter, best_pair_delimiter, best_extraction = (
        test_delimiter_combinations(binary_data, potential_delimiters, keys)
    )
    return best_kv_delimiter, best_pair_delimiter, best_extraction


class NVRAM(PyPlugin):
    # Nothing to do at runtime. Until we drop in HyperNVRam
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.fs_tar = self.get_arg("fs")

        nvram_keys = set(
            [b"wan-desc", b"wan_route", b"dhcp_wins", b"gui-version", b"sku_name"]
        )

    def uninit(self):
        print("[NVRAM] Examining console log...")
        nvram_keys = set()
        with open(f"{self.outdir}/console.log") as f:
            for line in f.readlines():
                if line.startswith("nvram_") and ":" in line:
                    _, tok = line.split(":")[:2]
                    tok = tok.lstrip(" ")
                    if " " in tok:
                        tok = tok.split(" ")[0]
                    if tok == "Unable":  # "Unable to open" error message
                        continue
                    nvram_keys.add(tok.strip().encode())

        print(f"[NVRAM] Detected {len(nvram_keys)} nvram key lookups")
        all_matches = {}  # Filename: dict of extracted values

        # For each file in the FS find the number of nvram keys that it contains
        keycount = {}  # filename -> {k: val}
        with tarfile.open(self.fs_tar, "r") as tar:
            keycount = {}  # filename -> count
            matching_files = []

            for member in tar.getmembers():
                if not member.isfile():
                    continue
                if member.path.startswith("./igloo"):
                    continue
                data = tar.extractfile(member.name).read()
                count = 0
                matches = set()
                for k in nvram_keys:
                    if k in data:
                        count += 1
                        matches.add(k)
                keycount[member.name] = (count, list(matches))

                # Now examine the top 10 most matching files
                matching_files.append((member.name, count, list(matches)))

            matching_files = sorted(matching_files, key=lambda x: x[1], reverse=True)[
                :10
            ]

            for k, count, matches in matching_files:
                if count <= 1:
                    continue
                print(f"[NVRAM] Guest file {k} has {count} matches")
                binary = tar.extractfile(k).read()

                try:
                    elffile = ELFFile(BytesIO(binary))
                except ELFError:
                    # Not a valid ELF. We could try parsing as plaintext
                    # but it's mabye just wrong? What about /etc/nvram kind of
                    # things?
                    continue

                rodata_section = elffile.get_section_by_name(".rodata")
                if not rodata_section:
                    print("[NVRAM]     no rodata section")
                    continue

                raw_data = rodata_section.data()

                d1, d2, extract = keyfinder(raw_data, matches)
                if extract is not None:
                    print(f"[NVRAM]     recovered {len(extract)} values")
                    all_matches[k] = extract

        # For each source file write out a unique nvram_potentials file
        for idx, filename in enumerate(all_matches):
            matches = all_matches[filename]
            # vals = {}
            # for key_name, key_val in matches.items():
            #    vals[key_name.decode()] = key_val
            vals = {key_name.decode(): key_val for key_name, key_val in matches.items()}
            with open(f"{self.outdir}/nvram_potentials_{idx}.yaml", "w") as f:
                yaml.dump(vals, f)

        if len(all_matches):
            with open(f"{self.outdir}/nvram_potentials_map.yaml", "w") as f:
                f.write("output_file,nvram_source_file\n")
                for idx, filename in enumerate(all_matches):
                    f.write(f"nvram_potentials_{idx}.yaml,{filename[1:]}\n")


"""
#TODO refactor as penguin plugin

# But we analyze console output after the fact
def propose_configs(config, result_dir, quiet=False):
    # Based off FirmAE's approach https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/inferDefault.py#L69
    nvram_gets = set()

    with open(join(result_dir, console_path), "rb") as f:
        # XXX this is broken
        for line in f.readlines():
            if line.startswith(b"nvram_get_buf:") and b"Unable to open" not in line and b"=" not in line:
                # 'nvam_get_buf: foo' should return 'foo'
                data = line.split(":")[1].strip()
                nvram_gets.add(data)

    if len(nvram_gets):
        print("Nvram gets:")
        for k in nvram_gets:
            print(k)

        # Try to find the nvram file in the base image
        fs_tar_path = config['base']['fs']
        # Open the tarfile
        tar = tarfile.open(fs_tar_path, "r")
        # Iterate through members
        for member in tar.getmembers():
            # For each file in the archive, check if it contains at least half of the nvram_gets
            # If so, we assume it's the nvram file
            # Read file
            if not member.isfile():
                continue

            match_count = 0
            data = tar.extractfile(member.name).read()

            for k in nvram_gets:
                if k in data:
                    match_count += 1

            if match_count > len(nvram_gets)//4:
                print("Potential nvram file:", member.name)

    return []
"""
