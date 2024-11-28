## Compile and install

### Compile and install devnet debug version

```
mkdir build_dev_debug && cd build_dev_debug
cmake .. 
make
```

### Compile and install devnet release version

```
mkdir build_dev_release && cd build_dev_release
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### Compile and install test net debug version

```
mkdir build_test_debug && cd build_test_debug
cmake .. -DTESTCHAIN=ON
make
```

### Compile and install test net RELEASE version

```
mkdir build_test_release && cd build_test_release
cmake .. -DTESTCHAIN=ON -DCMAKE_BUILD_TYPE=Release
make
```

### Compile and install the main network debug version

```
mkdir build_primary_debug && cd build_primary_debug
cmake .. -DPRIMARYCHAIN=ON 
make
```

### Compile and install the main network release version

```
mkdir build_primary_release && cd build_primary_release
cmake .. -DPRIMARYCHAIN=ON -DCMAKE_BUILD_TYPE=Release
make
```
