#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck

usage() {
    cat <<EOF
Usage: $0 INT:NUM_FAULT_EXPERIMENTS BOOL:SET_ZERO_FAULTS

Arguments:
  NUM_FAULT_EXPERIMENTS      Number of runs per parameter set (integer > 0)
  SET_ZERO_FAULTS            Whether to use set zero or set random faults.
                             Accepted values: true, false, yes, no, 1, 0, on, off

Examples:
  $0 1000 true
  $0 50000 false
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
    true|yes|1|on)  SET_ZERO_FAULTS=1 ;;
    false|no|0|off) SET_ZERO_FAULTS=0 ;;
    *)
        echo "Error: SET_ZERO_FAULTS must be true/false, yes/no, 1/0, or on/off"
        echo "Usage: $0 NUM_FAULT_EXPERIMENTS SET_ZERO_FAULTS [NUM_PARALLEL_PROCESSES]"
        exit 1
        ;;
esac

# Validate NUM_PARALLEL_PROCESSES
if ! [[ "$NUM_PARALLEL_PROCESSES" =~ ^[0-9]+$ ]] || [ "$NUM_PARALLEL_PROCESSES" -lt 1 ]; then
    echo "Error: NUM_PARALLEL_PROCESSES must be a positive integer"
    exit 1
fi

FORMATTED_NUM_FAULT_EXPERIMENTS=$(format_number "$NUM_FAULT_EXPERIMENTS")
echo "Starting fault simulation with $FORMATTED_NUM_FAULT_EXPERIMENTS runs per parameter set."
echo "Using $NUM_PARALLEL_PROCESSES parallel processes per configuration."

# Calculate experiments per process
EXPERIMENTS_PER_PROCESS=$((NUM_FAULT_EXPERIMENTS / NUM_PARALLEL_PROCESSES))
REMAINING_EXPERIMENTS=$((NUM_FAULT_EXPERIMENTS % NUM_PARALLEL_PROCESSES))

echo "Each process will run $(format_number $EXPERIMENTS_PER_PROCESS) experiments."
if [ $REMAINING_EXPERIMENTS -gt 0 ]; then
    echo "Last process will run $(format_number $((EXPERIMENTS_PER_PROCESS + REMAINING_EXPERIMENTS))) experiments."
fi

# --- Configuration: single instance to capture more traces ---
DEGREE=1
FAULTS=3
NUM_SECRETS_PER_ENCODING=1
OPT_FROBENIUS=1
OPT_ZENC=1
NUM_INJECTED_FAULTS=5

# build the CONF string
CONF="d${DEGREE}_e${FAULTS}_k${NUM_SECRETS_PER_ENCODING}_f${OPT_FROBENIUS}_z${OPT_ZENC}_i${NUM_INJECTED_FAULTS}"
if [ "$SET_ZERO_FAULTS" -eq 1 ]; then
    MODE_NAME="zero"
    MODE_DESC="set zero fault injections"
    BASE_DIR="set_zero_faults_${CONF}"
else
    MODE_NAME="rand"
    MODE_DESC="set random fault injections"
    BASE_DIR="set_random_faults_${CONF}"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/${MODE_NAME}_fault_simulation_log_${CONF}.txt"
> "$LOG_FILE"

log "Running with $MODE_DESC enabled for configuration ${CONF}."
mkdir -p "$BASE_DIR/csv"


# Change to the directory containing the tests
cd ../qemu_implementation || exit


################################
# BUILD PHASE                  #
################################
phase="BUILD"
start=$(date +%s.%N)

log "Building ${CONF} for $NUM_PARALLEL_PROCESSES processes (sequential)…"
# clean out any old builds
make completeclean >> "$LOG_FILE" 2>&1

build_status=0
for PROCESS_ID in $(seq 0 $((NUM_PARALLEL_PROCESSES - 1))); do
    # compute how many experiments this process will handle
    if [ $PROCESS_ID -eq $((NUM_PARALLEL_PROCESSES - 1)) ] && [ $REMAINING_EXPERIMENTS -gt 0 ]; then
        CURRENT_EXPERIMENTS=$((EXPERIMENTS_PER_PROCESS + REMAINING_EXPERIMENTS))
    else
        CURRENT_EXPERIMENTS=$EXPERIMENTS_PER_PROCESS
    fi

    log "  → PROCESS_ID=${PROCESS_ID}, experiments=${CURRENT_EXPERIMENTS}"
    # invoke the new build-config rule
    make prepare_outputs build-config \
         FAULT_LAOLA=1 \
         CONF="$CONF" \
         PROCESS_ID="$PROCESS_ID" \
         NUM_FAULT_EXPERIMENTS="$CURRENT_EXPERIMENTS" \
         SET_ZERO_FAULTS="$SET_ZERO_FAULTS" \
         >> "build_${PROCESS_ID}.log" 2>&1
    if [ $? -ne 0 ]; then
        log "Build failed for PROCESS_ID=${PROCESS_ID}"
        build_status=1
        break
    fi
done

# gather logs from building
for PROCESS_ID in $(seq 0 $((NUM_PARALLEL_PROCESSES - 1))); do
    if [ -f "build_${PROCESS_ID}.log" ]; then
        echo "=== Build log for PROCESS_ID=$PROCESS_ID ===" >> "$LOG_FILE"
        cat "build_${PROCESS_ID}.log" >> "$LOG_FILE"
        rm -f "build_${PROCESS_ID}.log"
    fi
done

if [ $build_status -ne 0 ]; then
    echo "Build failed. Check $LOG_FILE for details." | tee -a "$LOG_FILE"
    exit 1
fi

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

# Run multiple parallel processes for this configuration
for PROCESS_ID in $(seq 0 $((NUM_PARALLEL_PROCESSES - 1))); do
  (
    TEMP_FILE=$(mktemp)
    
    # Calculate experiments for this process
    if [ $PROCESS_ID -eq $((NUM_PARALLEL_PROCESSES - 1)) ] && [ $REMAINING_EXPERIMENTS -gt 0 ]; then
      CURRENT_EXPERIMENTS=$((EXPERIMENTS_PER_PROCESS + REMAINING_EXPERIMENTS))
    else
      CURRENT_EXPERIMENTS=$EXPERIMENTS_PER_PROCESS
    fi
    
    echo "" >> "$TEMP_FILE"
    echo "Starting tests for DEGREE=${DEGREE} FAULTS=${FAULTS} NUM_INJECTED_FAULTS=${NUM_INJECTED_FAULTS} PROCESS_ID=${PROCESS_ID}" >> "$TEMP_FILE"
    echo "Running $(format_number $CURRENT_EXPERIMENTS) experiments for this process" >> "$TEMP_FILE"
    echo "----------------------------------------" >> "$TEMP_FILE"

    FAULT_TRACE_FILE="fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}_${SET_ZERO_FAULTS}_p${PROCESS_ID}.txt"
    echo "Running make run CONF=$CONF with PROCESS_ID=$PROCESS_ID" >> "$TEMP_FILE"
    
    # Use the new Makefile approach with separate build directories
    make run PROCESS_ID=$PROCESS_ID CONF="$CONF" 2>&1 | tee "$FAULT_TRACE_FILE" >> "$TEMP_FILE"
    ret=$?

    if [ $ret -ne 0 ]; then
      echo "Error for $CONF process $PROCESS_ID, check log file for details." >> "$TEMP_FILE"
    else
      FAULT_TRACE_FULL_PATH="$(pwd)/$FAULT_TRACE_FILE"
      echo "generated fault trace to path $FAULT_TRACE_FULL_PATH"
      CSV_OUTPUT="$BASE_DIR/csv/fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}_p${PROCESS_ID}.csv"

      pushd ../fault_simulation >/dev/null
      python3 output_to_csv.py "$FAULT_TRACE_FULL_PATH" "$CSV_OUTPUT" >> "$TEMP_FILE" 2>&1
      echo "Converted $FAULT_TRACE_FILE to $CSV_OUTPUT" >> "$TEMP_FILE"
      popd >/dev/null

      if [ $? -eq 0 ]; then
        rm "$FAULT_TRACE_FILE"
        echo "CSV conversion succeeded for $CONF process $PROCESS_ID" >> "$TEMP_FILE"
      else
        echo "CSV conversion failed for $CONF process $PROCESS_ID" >> "$TEMP_FILE"
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

echo "Fault tracing started with $NUM_PARALLEL_PROCESSES processes per configuration. Waiting for completion..." | tee -a "$LOG_FILE"

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

# Merge CSV files from parallel processes before analysis
log "Merging CSV files from parallel processes..."
MERGED_CSV="csv/fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}.csv"

# Create merged CSV with header from first file
FIRST_CSV="csv/fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}_p0.csv"
if [ -f "$FIRST_CSV" ]; then
  head -n 1 "$FIRST_CSV" > "$MERGED_CSV"
  
  # Append data from all process CSV files (skip headers)
  for PROCESS_ID in $(seq 0 $((NUM_PARALLEL_PROCESSES - 1))); do
    PROCESS_CSV="csv/fault_trace_d${DEGREE}_e${FAULTS}_s${NUM_INJECTED_FAULTS}_p${PROCESS_ID}.csv"
    if [ -f "$PROCESS_CSV" ]; then
      tail -n +2 "$PROCESS_CSV" >> "$MERGED_CSV"
      rm "$PROCESS_CSV"  # Clean up individual process files
    fi
  done
  
  echo "Merged $(wc -l < "$MERGED_CSV") lines into $MERGED_CSV" | tee -a "$LOG_FILE"
fi

log "Starting analysis of fault traces. Output will be saved to $OUTPUT_FILE"
KEY="${DEGREE}_${FAULTS}_${NUM_INJECTED_FAULTS}"
TMP=$(mktemp)
TMP_FILES["$KEY"]="$TMP"

(
  echo "Analysis for d=${DEGREE}, e=${FAULTS}, s=${NUM_INJECTED_FAULTS} (${NUM_PARALLEL_PROCESSES} parallel processes)" > "$TMP"
  python3 ../analyse_fault_indices.py "$DEGREE" "$FAULTS" "$NUM_INJECTED_FAULTS" >> "$TMP" 2>&1
  ret=$?
  echo "----------------------------------------" >> "$TMP"
  exit $ret
) &
analysis_pids+=( $! )

# Wait for all analysis jobs
for pid in "${analysis_pids[@]}"; do
  if ! wait "$pid"; then
    analysis_status=1
  fi
done

# Merge temp files in the original order
KEY="${DEGREE}_${FAULTS}_${NUM_INJECTED_FAULTS}"
cat "${TMP_FILES[$KEY]}" >> "$OUTPUT_FILE"
rm -f "${TMP_FILES[$KEY]}"

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