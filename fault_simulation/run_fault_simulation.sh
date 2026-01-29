#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck

usage() {
    cat <<EOF
Usage: $0 INT:NUM_FAULT_EXPERIMENTS BOOL:SET_ZERO_FAULTS [INT:NUM_PARALLEL_PROCESSES]

Arguments:
  NUM_FAULT_EXPERIMENTS      Number of runs per parameter set (integer > 0)
  SET_ZERO_FAULTS            Whether to use set zero or set random faults.
                             Accepted values: true, false, yes, no, 1, 0, on, off
  NUM_PARALLEL_PROCESSES     (Optional) Number of parallel processes for trace
                             acquisition. Defaults to 1.

Examples:
  $0 1000 true
  $0 50000 false 4
EOF
    exit 1
}

format_number() {
    local num=$1
    if [ "$num" -ge 1000000 ]; then
        if [ $((num % 1000000)) -eq 0 ]; then
            echo "$((num / 1000000))M"
        else
            printf "%.1fM" "$(echo "scale=1; $num/1000000" | bc)"
        fi
    elif [ "$num" -ge 1000 ]; then
        if [ $((num % 1000)) -eq 0 ]; then
            echo "$((num / 1000))K"
        else
            printf "%.1fK" "$(echo "scale=1; $num/1000" | bc)"
        fi
    else
        echo "$num"
    fi
}
log() { echo "$@" | tee -a "$LOG_FILE"; }

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

NUM_FAULT_EXPERIMENTS=$1
SET_ZERO_FAULTS_INPUT=$2
NUM_PARALLEL_PROCESSES=${3:-1} 

# Check required args
if [[ -z "$NUM_FAULT_EXPERIMENTS" || -z "$SET_ZERO_FAULTS_INPUT" ]]; then
    echo "Error: Missing required arguments."
    usage
fi

# Convert boolean input to 0 or 1
case "${SET_ZERO_FAULTS_INPUT,,}" in
    true|yes|1|on)
        SET_ZERO_FAULTS=1
        ;;
    false|no|0|off)
        SET_ZERO_FAULTS=0
        ;;
    *)
        echo "Error: SET_ZERO_FAULTS must be true/false, yes/no, 1/0, or on/off"
        echo "Usage: $0 NUM_FAULT_EXPERIMENTS SET_ZERO_FAULTS"
        exit 1
        ;;
esac
FORMATTED_NUM_FAULT_EXPERIMENTS=$(format_number "$NUM_FAULT_EXPERIMENTS")
echo "Starting fault simulation with $FORMATTED_NUM_FAULT_EXPERIMENTS runs per parameter set."


# --- Configuration Arrays ---
DEGREE_VALUES=(1 2)
FAULTS_VALUES=(1 2 3)
NUM_SECRETS_PER_ENCODING_VALUES=(1)
OPT_FROBENIUS_VALUES=(1)
OPT_ZENC_VALUES=(1)
NUM_INJECTED_FAULTS_VALUES=(1 2 3 4 5)

if [ "$SET_ZERO_FAULTS" -eq 1 ]; then
    MODE_NAME="zero"
    MODE_DESC="set zero fault injections"
    BASE_DIR="set_zero_faults"
else
    MODE_NAME="rand"
    MODE_DESC="set random fault injections"
    BASE_DIR="set_random_faults"
fi
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/${MODE_NAME}_fault_simulation_log.txt"
> "$LOG_FILE"

log "Running with $MODE_DESC enabled."
mkdir -p "$BASE_DIR/csv"


# Change to the directory containing the tests
cd ../qemu_implementation || exit


################################
# BUILD PHASE                  #
################################
phase="BUILD"
start=$(date +%s.%N)

# Clean and rebuild everything
make clean
make FAULT_LAOLA=1 NUM_FAULT_EXPERIMENTS=$NUM_FAULT_EXPERIMENTS SET_ZERO_FAULTS=$SET_ZERO_FAULTS all -j >> "$LOG_FILE" 2>&1
wait


end=$(date +%s.%N)
elapsed=$(awk "BEGIN{printf \"%.2f\", $end - $start}")
log "[$phase] elapsed: ${elapsed}s"

################################
# TRACE PHASE                  #
################################
phase="TRACE"
start=$(date +%s.%N)

# Array to store background process IDs and overall test status
pids=()
overall_status=0


# Iterate over each combination of settings to generate fault traces
for OPT_FROBENIUS in "${OPT_FROBENIUS_VALUES[@]}"; do
  for OPT_ZENC in "${OPT_ZENC_VALUES[@]}"; do
    for NUM_SECRETS_PER_ENCODING in "${NUM_SECRETS_PER_ENCODING_VALUES[@]}"; do
      if [ "$OPT_ZENC" -eq 0 ] && [ "$NUM_SECRETS_PER_ENCODING" -gt 1 ]; then
        continue
      fi
      for DEGREE in "${DEGREE_VALUES[@]}"; do
        if [ "$NUM_SECRETS_PER_ENCODING" -gt 1 ] && [ "$NUM_SECRETS_PER_ENCODING" -gt $((DEGREE/2)) ]; then
          continue
        fi
        for FAULTS in "${FAULTS_VALUES[@]}"; do
          # Skip a specific problematic combination if needed.
          if [ "$NUM_SECRETS_PER_ENCODING" -eq 2 ] && [ "$DEGREE" -eq 4 ] && [ "$FAULTS" -eq 2 ]; then
            continue
          fi
          for NUM_INJECTED_FAULTS in "${NUM_INJECTED_FAULTS_VALUES[@]}"; do
            (
              TEMP_FILE=$(mktemp)
              CONF="d${DEGREE}_e${FAULTS}_k${NUM_SECRETS_PER_ENCODING}_f${OPT_FROBENIUS}_z${OPT_ZENC}_i${NUM_INJECTED_FAULTS}"

              echo "" >> "$TEMP_FILE"
              echo "Starting tests for DEGREE=${DEGREE} FAULTS=${FAULTS} NUM_INJECTED_FAULTS=${NUM_INJECTED_FAULTS}" >> "$TEMP_FILE"
              echo "----------------------------------------" >> "$TEMP_FILE"

              FAULT_TRACE_FILE="fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}_${SET_ZERO_FAULTS}.txt"
              echo "Running make run CONF=$CONF" >> "$TEMP_FILE"
              make run CONF="$CONF" 2>&1 | tee "$FAULT_TRACE_FILE" >> "$TEMP_FILE"
              ret=$?

              if [ $ret -ne 0 ]; then
                echo "Tests failed for $CONF" >> "$TEMP_FILE"
              else
                FAULT_TRACE_FULL_PATH="$(pwd)/$FAULT_TRACE_FILE"
                CSV_OUTPUT="$BASE_DIR/csv/fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}.csv"


                pushd ../fault_simulation >/dev/null
                python3 output_to_csv.py "$FAULT_TRACE_FULL_PATH" "$CSV_OUTPUT" >> "$TEMP_FILE" 2>&1
                echo "Converted $FAULT_TRACE_FILE to $CSV_OUTPUT" >> "$TEMP_FILE"
                popd >/dev/null

                if [ $? -eq 0 ]; then
                  rm "$FAULT_TRACE_FILE"
                  echo "CSV conversion succeeded for $CONF" >> "$TEMP_FILE"
                else
                  echo "CSV conversion failed for $CONF" >> "$TEMP_FILE"
                  ret=1
                fi
              fi

              echo "----------------------------------------" >> "$TEMP_FILE"
              echo "" >> "$TEMP_FILE"
              # line below can be uncommented to capture fault traces in log file, use only for debugging since this substantially increases disk space consumption
              #cat "$TEMP_FILE" >> "$LOG_FILE"  
              rm -f "$TEMP_FILE"
              exit $ret
            ) &
            pids+=($!)
          done
        done
      done
    done
  done
done

echo "Fault tracing started. Waiting for completion..." | tee -a "$LOG_FILE"

# Wait for all fault‑trace generation jobs
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    echo "Job with PID $pid failed." | tee -a "$LOG_FILE"
    overall_status=1
  fi
done

end=$(date +%s.%N)
elapsed=$(awk "BEGIN{printf \"%.2f\", $end - $start}")
log "[$phase] elapsed: ${elapsed}s"

echo "Fault tracing completed." | tee -a "$LOG_FILE"
pushd ../fault_simulation >/dev/null

################################
# ANALYSIS PHASE               #
################################
phase="ANALYSIS"
start=$(date +%s.%N)

cd "$BASE_DIR" || exit
OUTPUT_FILE="fault_analysis_report_${MODE_NAME}_values_${FORMATTED_NUM_FAULT_EXPERIMENTS}.log"

> "$OUTPUT_FILE"

declare -A TMP_FILES
declare -a analysis_pids
analysis_status=0

# Spawn one job per (DEGREE, FAULTS, NUM_INJECTED_FAULTS) to analyze the results of the fault traces
log "Starting analysis of fault traces. Output will be saved to $OUTPUT_FILE"
for DEGREE in "${DEGREE_VALUES[@]}"; do
  for FAULTS in "${FAULTS_VALUES[@]}"; do
    for NUM_INJECTED_FAULTS in "${NUM_INJECTED_FAULTS_VALUES[@]}"; do
      KEY="${DEGREE}_${FAULTS}_${NUM_INJECTED_FAULTS}"
      TMP=$(mktemp)
      TMP_FILES["$KEY"]="$TMP"

      (
        echo "Analysis for d=${DEGREE}, e=${FAULTS}, s=${NUM_INJECTED_FAULTS}" > "$TMP"
        python3 ../analyse_fault_indices.py "$DEGREE" "$FAULTS" "$NUM_INJECTED_FAULTS" >> "$TMP" 2>&1
        ret=$?
        echo "----------------------------------------" >> "$TMP"
        exit $ret
      ) &
      analysis_pids+=( $! )
    done
  done
done

# Wait for all analysis jobs
for pid in "${analysis_pids[@]}"; do
  if ! wait "$pid"; then
    analysis_status=1
  fi
done


# Merge temp files in the original order
for DEGREE in "${DEGREE_VALUES[@]}"; do
  for FAULTS in "${FAULTS_VALUES[@]}"; do
    for NUM_INJECTED_FAULTS in "${NUM_INJECTED_FAULTS_VALUES[@]}"; do
      KEY="${DEGREE}_${FAULTS}_${NUM_INJECTED_FAULTS}"
      cat "${TMP_FILES[$KEY]}" >> "$OUTPUT_FILE"
      rm -f "${TMP_FILES[$KEY]}"
    done
  done
done

echo "Fault analysis report generated into $OUTPUT_FILE"
popd >/dev/null
end=$(date +%s.%N)
elapsed=$(awk "BEGIN{printf \"%.2f\", $end - $start}")
log "[$phase] elapsed: ${elapsed}s"
# Combine test & analysis statuses
(( overall_status |= analysis_status ))


# Final status report
if [ $overall_status -ne 0 ]; then
  echo "Some jobs failed. See logs for details." | tee -a "$LOG_FILE"
  exit 1
else
  echo "All tests and analyses succeeded." | tee -a "$LOG_FILE"
  exit 0
fi
