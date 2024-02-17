Penguin iteration tests
---


These tests are designed to evaluate our ability to detect failures, propose mitigations, implement mitigations, and select a good result.

### Usage
```
docker build -t pandare/igloo:penguin ..
./test.sh
```

Or to run all tests for a given architecture:
```
./test.sh armel
```

Or to run one test on one architecture:
```
./test.sh armel pseudofile
```


## Psuedofile

* The guest runs the `hdparm` program which tries to open and issue ioctls on `/dev/missing`. The guest greps the output for an expected string that occurs when the program is happy and, when this occurs, runs `ps`.
* The iterative analysis should identify the missing device, add it, identify IOCTLs issued on it and model them such that the guest is happy with the output
* The most healthy config should have an IOCTL model for /dev/missing num 799 and have the `ps` command in its output


## Multiinit

* The guest contains two potential init programs, one does very little and the other does more.
* A shim of our 'static analysis' reports both these programs are potential inits that we need to try
* Through multiple tests we should identify the correct init based on the fact that one runs more programs.
