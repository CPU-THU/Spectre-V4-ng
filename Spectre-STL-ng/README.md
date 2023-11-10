# Introduction

In this Proof-of-Concept (PoC), we introduce the utilization of PSFP (Predictive Store Forwarding Predictor) to construct a novel variant of the Spectre-STL (aka Spectre V4) Attack, referred to as out-of-place Spectre-STL.

Specifically, this PoC demonstrates that the PSFP can be effectively employed to trigger a transient window without relying on the branch predictor or a faulty load. In contrast to the conventional Spectre-STL Attack, where the training of the PSFP requires repeated execution of the same store-load instruction pair, we showcase that an aliasing store-load pair can also be used to train the PSFP effectively. This novel approach enhances our understanding of Spectre attacks and highlights the potential security implications associated with the PSFP.

## Note
AMD has released a [document](https://www.amd.com/system/files/documents/security-analysis-predictive-store-forwarding.pdf) on the security analysis of AMD Predictive Store Forwarding (PSF) and stated that "it is possible that a store/load pair which does have a dependency may alias in the predictor with another store/load pair which does not." As far as we know, we are the first academic group to uncover the inner workings of PSF and to discover the method of training PSFP using an aliased store-load pair. This research provides valuable insights into the behavior and training of PSFP, contributing to a deeper understanding of its vulnerabilities and potential mitigation strategies.

## Build

A C compiler is required. For example, we use gcc 9.4.0 with make 4.2.1. No specific kernel or package dependencies and installations are required. The executable file named `spectre-stl-ofp` can be built through a simple command:

```shell
make
```

## Run

```shell
./spectre-stl-ofp
```

Expected result is as follows:

```
Search offset of prime entry:
Find collision offset as 31711
Putting 'Leaky PSFP: An out-of-place Spectre-STL attack!' in memory, address 0x55da454ef008
Reading 47 bytes:
Reading at address = 0x55da454ef008... Success: 0x4C='L' score=3 
Reading at address = 0x55da454ef009... Success: 0x65='e' score=3 
Reading at address = 0x55da454ef00a... Success: 0x61='a' score=3 
Reading at address = 0x55da454ef00b... Success: 0x6B='k' score=3 
Reading at address = 0x55da454ef00c... Success: 0x79='y' score=7 (second best: 0x9E='?' score=1)
Reading at address = 0x55da454ef00d... Success: 0x20=' ' score=3 
Reading at address = 0x55da454ef00e... Success: 0x50='P' score=3 
Reading at address = 0x55da454ef00f... Success: 0x53='S' score=3 
Reading at address = 0x55da454ef010... Success: 0x46='F' score=3 
Reading at address = 0x55da454ef011... Success: 0x50='P' score=3 
Reading at address = 0x55da454ef012... Success: 0x3A=':' score=3 
Reading at address = 0x55da454ef013... Success: 0x20=' ' score=3 
Reading at address = 0x55da454ef014... Success: 0x41='A' score=3 
Reading at address = 0x55da454ef015... Success: 0x6E='n' score=3 
Reading at address = 0x55da454ef016... Success: 0x20=' ' score=3 
Reading at address = 0x55da454ef017... Success: 0x6F='o' score=3 
Reading at address = 0x55da454ef018... Success: 0x75='u' score=3 
Reading at address = 0x55da454ef019... Success: 0x74='t' score=3 
Reading at address = 0x55da454ef01a... Success: 0x2D='-' score=7 (second best: 0x63='c' score=1)
Reading at address = 0x55da454ef01b... Success: 0x6F='o' score=3 
Reading at address = 0x55da454ef01c... Success: 0x66='f' score=3 
Reading at address = 0x55da454ef01d... Success: 0x2D='-' score=3 
Reading at address = 0x55da454ef01e... Success: 0x70='p' score=3 
Reading at address = 0x55da454ef01f... Success: 0x6C='l' score=3 
Reading at address = 0x55da454ef020... Success: 0x61='a' score=3 
Reading at address = 0x55da454ef021... Success: 0x63='c' score=3 
Reading at address = 0x55da454ef022... Success: 0x65='e' score=3 
Reading at address = 0x55da454ef023... Success: 0x20=' ' score=3 
Reading at address = 0x55da454ef024... Success: 0x53='S' score=3 
Reading at address = 0x55da454ef025... Success: 0x70='p' score=3 
Reading at address = 0x55da454ef026... Success: 0x65='e' score=3 
Reading at address = 0x55da454ef027... Success: 0x63='c' score=3 
Reading at address = 0x55da454ef028... Success: 0x74='t' score=3 
Reading at address = 0x55da454ef029... Success: 0x72='r' score=3 
Reading at address = 0x55da454ef02a... Success: 0x65='e' score=3 
Reading at address = 0x55da454ef02b... Success: 0x2D='-' score=3 
Reading at address = 0x55da454ef02c... Success: 0x53='S' score=3 
Reading at address = 0x55da454ef02d... Success: 0x54='T' score=3 
Reading at address = 0x55da454ef02e... Success: 0x4C='L' score=3 
Reading at address = 0x55da454ef02f... Success: 0x20=' ' score=3 
Reading at address = 0x55da454ef030... Success: 0x61='a' score=3 
Reading at address = 0x55da454ef031... Success: 0x74='t' score=3 
Reading at address = 0x55da454ef032... Success: 0x74='t' score=3 
Reading at address = 0x55da454ef033... Success: 0x61='a' score=3 
Reading at address = 0x55da454ef034... Success: 0x63='c' score=3 
Reading at address = 0x55da454ef035... Success: 0x6B='k' score=3 
Reading at address = 0x55da454ef036... Success: 0x21='!' score=3
```

### Note

In the out-of-order Spectre-STL implementation, it can be more challenging to achieve successful results due to the intricate design of the access mechanism in PSFP. Specifically, both the store and load Instruction Physical Addresses (IPA) are utilized in calculating the hash tag, making it difficult to find an aliased store-load pair in some cases (which also indicates that PSFP is much safer than SSBP). When this occurs, the output will indicate the following:

```
Search offset of prime entry:
Cannot find target. 
Cannot find prime entry, please try again.
```

To address this issue, we recommend the following solutions:

- Attempt more iterations until a collision is found, increasing the chances of locating an aliased store-load pair. 
- Modify the `PG_NUM` macro in `config.h` to a larger size. After making this change, rebuild the program and try again.
- Set the process affinity by executing `taskset -c <cpu-id> ./spectre-stl-ng`.

## Configurable parameters

Some configurable parameters are listed in file `config.h`. The parameters are divided into 2 categories. After modifying some of the parameters, please rebuild the PoC:

```
make clean & make
```

### System parameters

System parameters relate to the microarchitecture design and CPU frequency. There are 2 configurable system parameters in this PoC.

#### TYPE_H_BOUND

This judgment threshold is used to determine whether a non-aliased store-load pair is predicted as aliasing or non-aliasing. If the store-load pair is predicted as non-aliasing, the execution time is shorter; otherwise, the execution time is longer. 

For example, on AMD Ryzen 9 5900X with the following CPU frequency configuration, a feasible `TYPE_H_BOUND` is 190 (146 vs 205+). 

```
CPU MHz:                            2200.000
CPU max MHz:                        3700.0000
CPU min MHz:                        2200.0000
```

#### CACHE_HIT_THRESHOLD

This judgment threshold is used to determine whether a load hits in the cache or not. If the load hits in the cache, the execution time is shorter; otherwise, the execution time is longer. A feasible `CACHE_HIT_THRESHOLD` is 230 in our experiment enviroment.

### Attack parameters

Attack parameters relate to the attack performance, including success rate and leakage speed. Six parameters are configurable in this PoC.

#### SECRET

A string that is placed in the victim space.

#### LEAK_LEN

The lenght of bytes that will be leaked, which is suggested to be less than the length of the secret string.

#### CACHE_ST

Encoding granularity for Flush+Reload. The larger size will result in a better resolution, but requires a larger attacker-availble memory space. For more information, please refer to Flush+Reload Attack.

#### TRY_FOR_LEAK

Try times for secret leakage, which is 100 by dedault.

#### TRY_FOR_COLLISION

Try times for collision finding, which is 10 by dedault.

#### PG_NUM

Size of the empty executable page for code sliding, which is 8 by dedault.