# UP TO 50% OFF: Efficient Implementation of Polynomial Masking

This repository contains the implementation, evaluation, and fault simulation for the paper [**UP TO 50% OFF: Efficient Implementation of Polynomial Masking**](https://tches.iacr.org/index.php/TCHES/article/view/12697). For this work, we have implemented an AES Sbox protected with polynomial masking, using the LaOla multiplication. We provide a microcontroller C implementation for the STM32F415 board, a QEMU reference, Sage code for the generation of polynomial masking parameters, fault simulation scripts, and ChipWhisperer notebooks for side-channel evaluation. Using the code and usage instructions in this repository allows you to reproduce our paper's results. The ChipWhisperer evaluation requires physical hardware; the QEMU correctness tests and fault simulations are fully reproducible without it.

## ChipWhisperer Scope and Target
For the experiments in this paper we used the following devices:
- [ChipWhisperer-Husky](https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Husky.html)
- [CW308 UFO](https://chipwhisperer.readthedocs.io/en/latest/Targets/CW308%20UFO.html)
- [CW308T-STM32F](https://chipwhisperer.readthedocs.io/en/latest/chipwhisperer-target-cw308t/CW308T_STM32F/README.html) with the STM32F415RGT6 target

While our codebase can be adapted to other targets and capture scopes with minimal changes, it was designed for and evaluated on these devices. If you adapt to different hardware, you might have to adapt the following:
- We use the STM32F415RGT6 hardware AES to generate randombytes. If your target lacks hardware AES, replace the entropy source in `c_implementation/randombytes.c`.
- Adjustments to the scope and target need to be included in setup portions of `ChipWhisperer/ChipWhisperer_Evaluation.ipynb`.


## Usage Instructions
**Note**: While this setup supports standalone Docker usage, it is primarily designed for **VS Code** together with the **Dev Containers** extension. Using those will provide the smoothest experience.
1. **Requirements and Preparation**:
  We recommend installing VS Code and the Dev Containers extension before proceeding.
  The general setup we provide is platform-agnostic, as Dev Containers provide a fully self-contained dependency management, ensuring the reproducibility of our correctness tests and fault simulations. To reproduce the physical evaluation, the ChipWhisperer USB device needs to forwarded into the Dev Container, which is platform and version specific. We provide three options for USB forwarding:

   - **Linux**
    Simply install Docker and open the project in VS Code (see Step 2).

   - **Windows and macOS**

    USB access from Docker containers can be challenging because USB/IP support is limited on these platforms. USB forwarding is only required for physical evaluation with a connected ChipWhisperer device, if you are not running measurements on real hardware, you can use the container without USB forwarding. There is a workaround that uses a dedicated container to forward devices to other containers (see https://blog.golioth.io/usb-docker-windows-macos/).

    Finally, a common strategy is using a Linux virtual machine (e.g., via [Oracle VirtualBox](https://www.virtualbox.org/)) on a Windows or MacOS host and passing the ChipWhisperer USB device through to the VM. Inside the VM, install Docker and open the repository using VS Code with the Dev Containers extension.


1. **Open the Project in VSCode**:

      Open the directory in VS Code and select the pop-up: **Reopen in Container**.

      Or run `Ctrl + Shift + P -> Dev Containers: Reopen in Container`.


3. **Sage Setup Scripts**:
   Use the bash script 
   ```bash 
   bash sage_scripts/generate_vars.sh
   ``` 
   to set up necessary components like polynomial support points, Vandermonde matrices and lookup tables.

4. **Run and Evaluate ChipWhisperer Implementation**:
   Run the `ChipWhisperer/ChipWhisperer_Evaluation.ipynb` Jupyter notebook from top to bottom and follow its instructions to obtain benchmarking and TVLA results. Results of the TVLA are saved to `ChipWhisperer/t-test/t-test-plots`, where the TVLA plots of both the LaOla multiplication with 5M traces, and the full Sbox with 1M traces from our paper can be found. 

5. **Test Implementation Correctness in QEMU**:
    We provide a QEMU implementation in addition to our microcontroller implementation. The correctness of our implementation is tested by comparing masked computations against an unmasked reference function for parameters *d*={1,...,3}, *e*={0,...,3}, *k*=1 with Frobenius endomorphism enabled/disabled and our new zero-encodings, as well as, the zero-encodings from https://eprint.iacr.org/2023/1143.
    ```bash
    cd qemu_implementation
    bash regression_suite.sh -j <NUM_JOBS>
    ```
    Running this will test our components and produce either "All tests passed" or "Some tests failed" upon which `qemu_implementation/make_run_log.txt` can be examined for further detail.

6. **Fault Simulation of LaOla Multiplication**:
    We also evaluate the fault resistance of polynomial masking, as our QEMU implementation is also augmented with the ability to perform simulated fault injection on any field operation. Specifically, the result of any field operation can be set to a value provided by the adversary, thus enabling set-value fault attacks. The experiments in our paper perform set-zero, as well as, set-random value fault injection on the LaOla multiplication and evaluate if and how the outcome of a faulted and unfaulted run, using the same randomness, differ. We consider a fault *effective* when the encoded values of both runs differ and a fault *detected* iff one of the higher-order coefficients of the result are non-zero. We thus classify three types of faults:
    1. *detected faults*: one or more higher-order coefficients are non-zero allowing the fault to be detected
    2. *effective undetected faults*: fault was not detected and managed to change the encoded secret value
    3. *ineffective undetected faults*: fault was not detected but did not change the encoded secret value

    Our fault simulation allows performing randomized set-zero/random fault injection by doing the following:
    ```bash
    cd fault_simulation
    bash run_fault_simulation.sh <NUM_FAULT_EXPERIMENTS> <SET_ZERO_FAULTS>
    ```
    Here `NUM_FAULT_EXPERIMENTS` specifies the number of runs to perform per parameter set and `SET_ZERO_FAULTS` is a bool that selects set-zero faults when true and set-random faults when false.
    The simulations in our paper perform a sweep across *d*={1,2}, *e*={1,2,3}, *s*={1,...,5}, where *s* denotes the number of injected faults, with 100M runs per parameter set for both set-zero and set-random faults. Our results are saved under `set_random_faults/fault_analysis_report_rand_values_100M.log` and `set_zero_faults/fault_analysis_report_zero_values_100M.log`. The associated `.csv` traces are saved under `set_{random,zero}_faults/csv` and log files are saved in the `fault_simulation` directory. To replicate these experiments run:
    ```bash
    bash run_fault_simulation.sh 100000000 true
    bash run_fault_simulation.sh 100000000 false
    ```
    Note that these experiments and their tracing are computationally heavy and required 8 hours and 500 GB of space on our server-grade machine. We recommend either compressing or deleting the resulting `.csv` files in the respective `set_{random,zero}_faults/csv` directories after runs.

    Furthermore, our paper includes a more extensive run of the *d*=1, *e*=3, *s*=5 parameter set that supports multithreaded trace acquisition.
    ```bash
    bash run_fault_simulation_d1_e3_s5.sh <NUM_FAULT_EXPERIMENTS> <SET_ZERO_FAULTS> <NUM_THREADS>
    ```
    Note: the script spawns NUM_THREADS worker processes for trace generation plus a small amount of auxiliary I/O work. Results depend on NUM_THREADS because the RNG seed is derived from the worker process ID. Our results were produced by merging two runs with 5B traces that were using different, randomly-generated, seeds.




## Repository Structure
Here, we outline the general structure of our codebase in case you want to modify or use some of its components:

- **`.devcontainer/`**:
  - `Containerfile`: Container to be used with the VSCode Dev Container extension or Docker/alternatives.
  - `devcontainer.json`: Defines the environment and features to be used with VSCode Dev Container.

- **`c_implementation/`**:
  Contains the C code and its dependencies for the microcontroller.
    - **`crypto/poly_masked_sbox/`**: Contains our code for the poly masked Sbox and necessary helper functions/parameter files.
    - **`simpleserial`**: ChipWhisperer simpleserial communication protocol.
    - **`simpleserial-polymasked-sbox-implementation`**: Our entrypoint for host-to-board communication as a wrapper around the Sbox.

- **`ChipWhisperer/`**:
  Contains our python notebooks for flashing the implementation, running test cases, collecting traces, and running TVLA:
    - **`poly_masking_setup/`**: Python files containing parameter specific values used for polynomial masking setup.
    - **`Setup_Scripts/`**: Jupyter notebooks to configure target and capture scope for ChipWhisperer devices.
    - **`t-test/`**: Traces, results and plots for TVLA.
    - **`ChipWhisperer_Evaluation.ipynb`**: Jupyter notebook containing code for correctness testing, benchmarking and TVLA evaluation.

- **`fault_simulation/`**:
  Our scripts to perform set-zero and set-random simulated fault injection and analyze the results.
    - **`set_random_faults`**: Results of fault injection setting field operation outputs to random values with 100 million runs per parameter set.
    - **`set_zero_faults`**: Results of fault injection setting field operation outputs to zero with 100 million runs per parameter set.
    - **`run_fault_simulation.sh`**: Bash script that builds the QEMU implementation with fault injection enabled and performs a parameter sweep for the specified set-zero/random fault type and number of runs.
    - **`run_fault_simulation_d1_e3_s5.sh`**: Bash script that builds the QEMU implementation with fault injection enabled and multi-threaded fault injection for *d*=1, *e*=3, *s*=5 with specified set-zero/random fault type and number of runs.
    - **`output_to_csv.py` and `analyse_fault_indices.py`: Python code to aggregate and interpret fault simulation traces.
  
- **`qemu_implementation/`**:
  - **`src/`**: Our C implementation closely matching the one in `c_implementation/` that exhaustively checks correctness using `regression_suite.sh` and performs simulated fault injection on field operations using experiments defined in `laola_fault_injection_experiments.c`. Differences here are the usage of XORSHIFT32 as a PRNG and the additional fault injection capabilities included in `poly_masked_sbox.c`.

- **`sage_scripts/`**:
  Contains our setup scripts for generating:
    - **`generate_python_variables.sage`**: Lookup tables and parameter variables for polynomial masking.
    - **`optimized_log_table.sage`**: Log and antilog lookup tables for GF(2^8).
    - **`generate_vars.sh`**: Generate necessary parameter variables and LUTs for `ChipWhisperer/ChipWhisperer_Evaluation.ipynb`:
    - **`poly_masking_lib.sage`**: Provide functions to generate support points stable under the Frobenius endomorphism and other variables used in Laola and BGW.
    - **`polynomial_masking_reference_implementation_sage.ipynb`**: Notebook for deriving and validating optimized zero-encoding constructions used in polynomial masking.

