#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck

# default is max number of threads
JOBS=$(nproc)

usage() {
  echo "Usage: $0 [-j JOBS]"
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -j|--jobs)
      JOBS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

# Validate JOBS
if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [[ "$JOBS" -lt 1 ]]; then
  echo "Invalid JOBS value: $JOBS (must be a positive integer)"
  exit 2
fi


# Define the configurations for possible combinations of parameters
DEGREE_VALUES=(1 2 3)
FAULTS_VALUES=(0 1 2 3)
NUM_SECRETS_PER_ENCODING_VALUES=(1)
OPT_FROBENIUS_VALUES=(1 0)
OPT_ZENC_VALUES=(1 0)

# Log file to store the output
LOG_FILE="make_run_log.txt"

# Clear the log file
rm -f "$LOG_FILE"

make clean

# Build all targets in parallel 
make all -j"$JOBS" >> "$LOG_FILE" 2>&1

# Array to store background job process IDs
pids=()

wait_for_slot() {
  # Wait until the number of running background jobs is < JOBS
  while (( $(jobs -pr | wc -l) >= JOBS )); do
    wait -n
  done
}


# Iterate over each combination of settings and test correctness
for OPT_FROBENIUS in "${OPT_FROBENIUS_VALUES[@]}"; do
  for OPT_ZENC in "${OPT_ZENC_VALUES[@]}"; do
    for NUM_SECRETS_PER_ENCODING in "${NUM_SECRETS_PER_ENCODING_VALUES[@]}"; do
      # old gadgets dont permit packed secret sharing
      if [ "$OPT_ZENC" -eq 0 ] && [ "$NUM_SECRETS_PER_ENCODING" -gt 1 ]; then
        continue 
      fi
      for DEGREE in "${DEGREE_VALUES[@]}"; do
        # packed secret sharing requires floor(d/2) >= s 
        if [ "$NUM_SECRETS_PER_ENCODING" -gt 1 ] && [ "$NUM_SECRETS_PER_ENCODING" -gt $((DEGREE/2)) ]; then
          continue
        else
          for FAULTS in "${FAULTS_VALUES[@]}"; do
          wait_for_slot
            (
              # Create a temporary file to group the output
              TEMP_FILE=$(mktemp)
              # build a configuration string to index the correct executable
              CONF="d${DEGREE}_e${FAULTS}_k${NUM_SECRETS_PER_ENCODING}_f${OPT_FROBENIUS}_z${OPT_ZENC}_i0"
              echo "Running test: OPT_FROBENIUS=${OPT_FROBENIUS}, OPT_ZENC=${OPT_ZENC}, NUM_SECRETS_PER_ENCODING=${NUM_SECRETS_PER_ENCODING}, DEGREE=${DEGREE}, FAULTS=${FAULTS}" >> "$TEMP_FILE"
              echo "Configuration: $CONF" >> "$TEMP_FILE"
              
              # Run the test and capture its output
              make run CONF="$CONF" >> "$TEMP_FILE" 2>&1
              if [ $? -ne 0 ]; then
                echo "Tests failed for OPT_FROBENIUS=${OPT_FROBENIUS}, OPT_ZENC=${OPT_ZENC}, NUM_SECRETS_PER_ENCODING=${NUM_SECRETS_PER_ENCODING}, DEGREE=${DEGREE}, FAULTS=${FAULTS}" >> "$TEMP_FILE"
                ret=1
              else
                echo "Tests succeeded for OPT_FROBENIUS=${OPT_FROBENIUS}, OPT_ZENC=${OPT_ZENC}, NUM_SECRETS_PER_ENCODING=${NUM_SECRETS_PER_ENCODING}, DEGREE=${DEGREE}, FAULTS=${FAULTS}" >> "$TEMP_FILE"
                ret=0
              fi
              echo "----------------------------------------" >> "$TEMP_FILE"
              echo "" >> "$TEMP_FILE"

              # Print the output to the terminal
              echo "==== Test Output for ${CONF} ===="
              cat "$TEMP_FILE"
              echo "==== End of Test Output for ${CONF} ===="
              echo ""

              # Append the entire grouped output from the temporary file to the log file
              cat "$TEMP_FILE" >> "$LOG_FILE"
              rm -f "$TEMP_FILE"
              exit $ret
            ) &
            pids+=($!)
          done
        fi
      done
    done
  done
done

# Wait for all background jobs and aggregate exit statuses
overall_status=0
for pid in "${pids[@]}"; do
    # if at least one job returned a non-zero exit code then we establish that some tests failed
    if ! wait "$pid"; then
        overall_status=1
    fi
done

if [ $overall_status -ne 0 ]; then
  echo "Some tests failed. Check $LOG_FILE for details." | tee -a "$LOG_FILE"
  exit 1
else
  echo "All tests passed. Check $LOG_FILE for details." | tee -a "$LOG_FILE"
  exit 0
fi
