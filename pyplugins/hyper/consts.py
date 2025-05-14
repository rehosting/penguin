from penguin import plugins

enum_names = [
    "HYPER_OP",
    "portal_type",
    "igloo_hypercall_constants",
    "hyperfs_ops",
    "hyperfs_file_ops",
]

for name in enum_names:
    hyperconsts = plugins.kffi.get_enum_dict(name)
    assert len(hyperconsts.items()) > 0, f"Failed to get enum {name}"

    for i,j in hyperconsts.items():
        globals()[i] = j