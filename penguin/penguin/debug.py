import pickle
from .graphs import Configuration, Mitigation, Failure, ConfigurationGraph


def main(pkl):
    with open(pkl, 'rb') as f:
        g = pickle.load(f)

    # How many nodes of each type are there?
    # We'll use isinstance of Configuration, Mitigation, and Failure
    # to determine the type of each node

    nodes = [x[1]['object'] for x in g.nodes(data=True)]
    configs =     [x for x in nodes if isinstance(x, Configuration)]
    mitigations = [x for x in nodes if isinstance(x, Mitigation)]
    failures =    [x for x in nodes if isinstance(x, Failure)]

    print(f"Number of configurations: {len(configs)}")
    print(f"Number of mitigations: {len(mitigations)}")
    print(f"Number of failures: {len(failures)}")

    import ipdb; ipdb.set_trace()

    

if __name__ == '__main__':
    from sys import argv
    main(argv[1])