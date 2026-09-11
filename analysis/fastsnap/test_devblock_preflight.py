#!/usr/bin/env python3
"""The API preflight must find the names, under penguin's load model.

Run: python3 analysis/fastsnap/test_devblock_preflight.py

This exists because the preflight failed twice, both times in ways that would
have left it reporting health while checking nothing:

 1. v1 enumerated the required names by hand. The next commit added
    FASTSNAP_RESTORE_VERIFY to the code and not to the list, and three runs
    died on the AttributeError the check exists to prevent.
 2. v2 derived them with inspect.getsource(), which penguin makes unavailable
    -- it execs a plugin into a synthetic `plugin_file` module, so getsource
    raises TypeError. v2 caught only OSError, and its fallback was an empty
    set, which subtracts to "nothing missing".

So the test asserts two things a green run cannot tell you apart from: that
the names are found AT ALL, and that they are found WITHOUT source access.
"""
import ast
import inspect
import pathlib
import sys
import types

HERE = pathlib.Path(__file__).resolve().parent


def load_class_as_penguin_does():
    """Exec the plugin into a synthetic module, so it has no source file."""
    tree = ast.parse((HERE / "devblock.py").read_text())
    cls_node = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    cls_node.bases = []              # the penguin Plugin base is not importable here
    cls_node.decorator_list = []
    mod = types.ModuleType("plugin_file")
    sys.modules["plugin_file"] = mod
    stdlib = [n for n in tree.body if isinstance(n, ast.Import)
              and n.names[0].name.split(".")[0] in
              ("json", "os", "re", "statistics", "time")]
    body = ast.Module(body=stdlib + [cls_node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(body), "plugin_file", "exec"),
         mod.__dict__)
    return mod.__dict__[cls_node.name]


def main():
    cls = load_class_as_penguin_does()

    try:
        inspect.getsource(cls)
        print("WARNING: getsource() worked, so this is a WEAKER test than the "
              "condition penguin actually imposes")
    except Exception as exc:
        print(f"ok  getsource unavailable ({type(exc).__name__}), as under penguin")

    names = cls._api_names_used()

    assert names, ("the preflight found NO names -- it is inert, which is the "
                   "failure mode it exists to prevent")
    print(f"ok  found {len(names)} names without source access")

    # The specific name whose absence from the hand-kept list cost three runs.
    assert "FASTSNAP_RESTORE_VERIFY" in names, \
        "missed FASTSNAP_RESTORE_VERIFY -- the exact regression this guards"
    required = {"FASTSNAP_TAKE", "FASTSNAP_RESTORE", "FASTSNAP_PROBE",
                "fastsnap_schedule", "fastsnap_seq", "fastsnap_last_rc",
                "fastsnap_last_us", "fastsnap_last_digest",
                "fastsnap_block_size", "fastsnap_section_count",
                "fastsnap_set_denylist", "fastsnap_section_names"}
    missing = sorted(required - names)
    assert not missing, f"preflight would not check: {missing}"
    print(f"ok  includes FASTSNAP_RESTORE_VERIFY and all {len(required)} others")

    # NEGATIVE CONTROL. A class that touches no fastsnap API must yield
    # nothing. Without this, a matcher that simply returned every attribute
    # name it saw would pass every assertion above.
    impl = cls.__dict__["_api_names_used"].__func__

    class Unrelated:
        def m(self):
            return self.panda.load_snapshot("x") + self.panda.other_thing()

    assert impl(Unrelated) == set(), \
        "matcher fires on unrelated attribute names -- it is not specific"
    print("ok  negative control: a class using no fastsnap API yields none")

    # And it must find one that IS there, in a class it has never seen.
    class UsesOne:
        def m(self):
            return self.panda.fastsnap_seq()

    assert impl(UsesOne) == {"fastsnap_seq"}, impl(UsesOne)
    print("ok  positive control: finds fastsnap_seq in an unseen class")

    print("\nPASS")


if __name__ == "__main__":
    main()
