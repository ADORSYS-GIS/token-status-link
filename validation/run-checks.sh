#!/usr/bin/env bash
#
# Reproducible validation for the token-status-link code-scan findings 1-7.
#
# Every check asserts the FIXED behaviour, so:
#   * before the fix -> check FAILs  (proves the issue is real)
#   * after the fix  -> check PASSes (proves the fix works)
#
# Usage:
#   ./validation/run-checks.sh                   run everything; exit 0 iff all checks pass
#   ./validation/run-checks.sh --expect broken   exit 0 iff every selected finding still reproduces (pre-fix run)
#   ./validation/run-checks.sh --expect fixed    exit 0 iff every selected finding is fixed (post-fix run)
#   ./validation/run-checks.sh --only 1,4        run a subset (finding numbers 1-7)
#
# See validation/README.md for what each check asserts and the ticket grouping.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.." || exit 2 # token-status-link module root

LOG_DIR="target/validation"
mkdir -p "${LOG_DIR}"

MVN="./mvnw"
[[ -x ./mvnw ]] || MVN="sh ./mvnw"

ALL_FINDINGS=(1 2 3 4 5 6 7)

usage() {
    cat <<'EOF'
Usage: run-checks.sh [--expect broken|fixed] [--only 1,2,...] [--help]

  --expect broken   exit 0 iff every selected finding still reproduces (use BEFORE the fix)
  --expect fixed    exit 0 iff every selected finding is fixed        (use AFTER the fix)
  --only LIST       comma-separated finding numbers (1-7) to run
  --help            show this help

Without --expect the script exits 0 iff all selected checks pass.

Checks 1, 2, 4, 5, 7a are JUnit classes in
  src/test/java/io/github/adorsysgis/keycloakstatuslist/validation/*Check.java
run via -Dtest (the *Check suffix keeps them out of normal `mvn test` builds).
Checks 3, 6, 7b are shell/grep checks against pom.xml and docs/.
Maven output is written to target/validation/.
EOF
}

EXPECT=""
ONLY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --expect)
            EXPECT="${2:-}"; shift 2 ;;
        --expect=*)
            EXPECT="${1#*=}"; shift ;;
        --only)
            ONLY="${2:-}"; shift 2 ;;
        --only=*)
            ONLY="${1#*=}"; shift ;;
        -h | --help)
            usage; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -n "${EXPECT}" && "${EXPECT}" != "broken" && "${EXPECT}" != "fixed" ]]; then
    echo "Invalid --expect value '${EXPECT}' (expected 'broken' or 'fixed')" >&2
    exit 2
fi

SELECTED=("${ALL_FINDINGS[@]}")
if [[ -n "${ONLY}" ]]; then
    IFS=',' read -r -a SELECTED <<< "${ONLY}"
    for n in "${SELECTED[@]}"; do
        if [[ ! "${n}" =~ ^[1-7]$ ]]; then
            echo "Invalid finding number '${n}' in --only (expected 1-7)" >&2
            exit 2
        fi
    done
fi

is_selected() {
    local wanted="$1" n
    for n in "${SELECTED[@]}"; do
        [[ "${n}" == "${wanted}" ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Run the JUnit-based checks (findings 1, 2, 4, 5, 7a) in a single mvn call
# ---------------------------------------------------------------------------
java_class_for() {
    case "$1" in
        1) echo "Finding01ConfigParsingCheck" ;;
        2) echo "Finding02HttpClientLifecycleCheck" ;;
        4) echo "Finding04ConfigLoggingCheck" ;;
        5) echo "Finding05ResponseHeaderLogCheck" ;;
        7) echo "Finding07aTestHelperCheck" ;;
        *) echo "" ;;
    esac
}

JAVA_CLASSES=()
for n in "${SELECTED[@]}"; do
    class="$(java_class_for "${n}")"
    [[ -n "${class}" ]] && JAVA_CLASSES+=("${class}")
done

if [[ ${#JAVA_CLASSES[@]} -gt 0 ]]; then
    # Drop stale reports first so a compile/harness error cannot masquerade as a previous result.
    for class in "${JAVA_CLASSES[@]}"; do
        rm -f "target/surefire-reports/io.github.adorsysgis.keycloakstatuslist.validation.${class}.txt"
    done
    patterns="$(IFS=,; echo "${JAVA_CLASSES[*]}")"
    ${MVN} -B test -Dtest="${patterns}" > "${LOG_DIR}/java-checks.log" 2>&1
fi

# Sets JAVA_STATUS / JAVA_DETAIL for the given *Check class.
java_check_status() {
    local class="$1"
    local report="target/surefire-reports/io.github.adorsysgis.keycloakstatuslist.validation.${class}.txt"
    if [[ ! -f "${report}" ]]; then
        JAVA_STATUS="ERROR"
        JAVA_DETAIL="check did not run (compile or harness error) - see ${LOG_DIR}/java-checks.log"
    elif grep -qE 'Tests run: [0-9]+, Failures: 0, Errors: 0' "${report}"; then
        JAVA_STATUS="PASS"
        JAVA_DETAIL="all assertions satisfied (${class})"
    else
        JAVA_STATUS="FAIL"
        JAVA_DETAIL="$(grep -m1 -oE 'Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+' "${report}") - issue reproduced (details: ${report})"
    fi
}

# ---------------------------------------------------------------------------
# Shell-based checks (findings 3, 6, 7b)
# ---------------------------------------------------------------------------
check_finding_3() {
    local log="${LOG_DIR}/junit-dependency-tree.log"
    ${MVN} -B dependency:tree -Dincludes=org.junit.jupiter:junit-jupiter-params > "${log}" 2>&1
    local mvn_exit=$?
    local expected actual
    expected="$(sed -n 's/.*<junit\.version>\([^<]*\)<\/junit\.version>.*/\1/p' pom.xml | head -n1)"
    actual="$(grep -oE 'junit-jupiter-params:jar:[0-9][0-9A-Za-z._-]*' "${log}" | head -n1 | sed 's/.*jar://')"
    if [[ ${mvn_exit} -ne 0 ]]; then
        SUB_STATUS="ERROR"
        SUB_DETAIL="mvn dependency:tree failed - see ${log}"
    elif [[ -z "${actual}" ]]; then
        SUB_STATUS="FAIL"
        SUB_DETAIL="junit-jupiter-params not found in the dependency tree - see ${log}"
    elif [[ "${actual}" != "${expected}" ]]; then
        SUB_STATUS="FAIL"
        SUB_DETAIL="resolved ${actual}, expected ${expected} (junit.version property in pom.xml); the hardcoded version overrides the JUnit BOM"
    else
        SUB_STATUS="PASS"
        SUB_DETAIL="resolved ${actual} matches junit.version ${expected}"
    fi
}

check_finding_6() {
    local doc="docs/technical-reference.md"
    local missing=()
    grep -q 'mappingStatus' "${doc}" || missing+=("mappingStatus field not documented")
    grep -q 'countsTowardQuota' "${doc}" || missing+=("countsTowardQuota field not documented")
    grep -i 'activeCount' "${doc}" | grep -qiE 'no mapping|unmapped' ||
        missing+=("activeCount description does not mention credentials with no mapping")
    if [[ ${#missing[@]} -eq 0 ]]; then
        SUB_STATUS="PASS"
        SUB_DETAIL="mappingStatus and countsTowardQuota documented; activeCount wording covers unmapped credentials"
    else
        local joined=""
        local item
        for item in "${missing[@]}"; do
            joined+="${joined:+, }${item}"
        done
        SUB_STATUS="FAIL"
        SUB_DETAIL="in ${doc}: ${joined}"
    fi
}

check_finding_7b() {
    local file="src/test/java/io/github/adorsysgis/keycloakstatuslist/jpa/repository/StatusListRepositoryTest.java"
    if [[ ! -f "${file}" ]]; then
        SUB_STATUS="FAIL"
        SUB_DETAIL="missing ${file} (no repository-level tests exist at all)"
        return
    fi
    local count
    count="$(grep -c '@Test' "${file}" || true)"
    if [[ "${count}" -ge 3 ]]; then
        SUB_STATUS="PASS"
        SUB_DETAIL="${count} @Test methods in StatusListRepositoryTest"
    else
        SUB_STATUS="FAIL"
        SUB_DETAIL="only ${count} @Test method(s) in StatusListRepositoryTest, need >= 3 (next-index reservation, list-id rollover, latest-mapping locking)"
    fi
}

# ERROR beats FAIL beats PASS.
worst_status() {
    if [[ "$1" == "ERROR" || "$2" == "ERROR" ]]; then
        echo "ERROR"
    elif [[ "$1" == "FAIL" || "$2" == "FAIL" ]]; then
        echo "FAIL"
    else
        echo "PASS"
    fi
}

# ---------------------------------------------------------------------------
# Evaluate every selected finding
# ---------------------------------------------------------------------------
IDS=()
TITLES=()
STATUSES=()
DETAILS=()

record() {
    IDS+=("$1")
    TITLES+=("$2")
    STATUSES+=("$3")
    DETAILS+=("$4")
}

title_for() {
    case "$1" in
        1) echo "Malformed numeric realm attributes break issuance (raw NumberFormatException)" ;;
        2) echo "HTTP client created per mapper construction, never closed" ;;
        3) echo "junit-jupiter-params pinned below the JUnit BOM version" ;;
        4) echo "WARN logged on every issuance when status-list-max-entries is unset" ;;
        5) echo "Response headers logged as JVM array identity" ;;
        6) echo "Docs missing mappingStatus/countsTowardQuota; activeCount wording" ;;
        7) echo "Test gaps: silent setPrivateField + missing StatusListRepositoryTest" ;;
    esac
}

SUB_STATUS=""
SUB_DETAIL=""

for n in 1 2 3 4 5 6 7; do
    is_selected "${n}" || continue
    case "${n}" in
        1 | 2 | 4 | 5)
            java_check_status "$(java_class_for "${n}")"
            record "${n}" "$(title_for "${n}")" "${JAVA_STATUS}" "${JAVA_DETAIL}"
            ;;
        3)
            check_finding_3
            record "${n}" "$(title_for "${n}")" "${SUB_STATUS}" "${SUB_DETAIL}"
            ;;
        6)
            check_finding_6
            record "${n}" "$(title_for "${n}")" "${SUB_STATUS}" "${SUB_DETAIL}"
            ;;
        7)
            java_check_status "$(java_class_for 7)"
            st="${JAVA_STATUS}"; detail="${JAVA_DETAIL}"
            check_finding_7b
            st="$(worst_status "${st}" "${SUB_STATUS}")"
            detail="7a: ${detail} | 7b: ${SUB_DETAIL}"
            record "${n}" "$(title_for "${n}")" "${st}" "${detail}"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
total=${#IDS[@]}
passes=0
failures=0
errors=0
for i in "${!IDS[@]}"; do
    case "${STATUSES[$i]}" in
        PASS) passes=$((passes + 1)) ;;
        ERROR) errors=$((errors + 1)) ;;
        *) failures=$((failures + 1)) ;;
    esac
done

echo
echo "=============================================================================="
echo " token-status-link finding validation (logs: target/validation/)"
echo "=============================================================================="
for i in "${!IDS[@]}"; do
    printf ' %s) %-6s %s\n' "${IDS[$i]}" "${STATUSES[$i]}" "${TITLES[$i]}"
    printf '      %s\n' "${DETAILS[$i]}"
done
echo "------------------------------------------------------------------------------"
printf ' Result: %d/%d PASS, %d/%d FAIL, %d ERROR\n' "${passes}" "${total}" "${failures}" "${total}" "${errors}"
echo "   FAIL  = issue still present (expected BEFORE the fix)"
echo "   PASS  = issue fixed         (expected AFTER the fix)"
echo "   ERROR = check could not run (fix the harness first)"
echo "=============================================================================="

case "${EXPECT}" in
    broken)
        if [[ ${passes} -eq 0 && ${errors} -eq 0 ]]; then
            echo "OK: all ${total} selected findings reproduce - the issues are real."
            exit 0
        fi
        echo "PROBLEM: --expect broken, but $((passes + errors)) check(s) did not reproduce the issue:"
        for i in "${!IDS[@]}"; do
            [[ "${STATUSES[$i]}" != "FAIL" ]] && echo "  ${IDS[$i]}) ${STATUSES[$i]}"
        done
        exit 1
        ;;
    fixed)
        if [[ ${failures} -eq 0 && ${errors} -eq 0 ]]; then
            echo "OK: all ${total} selected findings are fixed."
            exit 0
        fi
        echo "PROBLEM: --expect fixed, but $((failures + errors)) check(s) are not fixed:"
        for i in "${!IDS[@]}"; do
            [[ "${STATUSES[$i]}" != "PASS" ]] && echo "  ${IDS[$i]}) ${STATUSES[$i]} - ${TITLES[$i]}"
        done
        exit 1
        ;;
    *)
        if [[ ${failures} -eq 0 && ${errors} -eq 0 ]]; then
            exit 0
        fi
        exit 1
        ;;
esac
