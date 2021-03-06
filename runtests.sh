#!/bin/bash
#
# Run the Pyflame test suite.
#
# If invoked without arguments, this will make a best effort to run the test
# suite against python2 and python3. If you would like to force the test suite
# to run against a specific version of python, invoke with the python
# interpreter names as arguments. These should be strings suitable for passing
# to virtualenv -p.

set -e

ENVDIR="./.test_env"
trap 'rm -rf ${ENVDIR}' EXIT

while getopts ":hx" opt; do
  case $opt in
    h)
      echo "Usage: $0 [-h] [-x] python..."
      exit 1
      ;;
    x)
      set -x
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
  esac
done

shift "$((OPTIND-1))"

# Run tests using pip; $1 = python version
run_pip_tests() {
  local activated=0
  if [ -z "${VIRTUAL_ENV}" ]; then
    rm -rf "${ENVDIR}"
    virtualenv -q -p "$1" "${ENVDIR}" &>/dev/null

    # shellcheck source=/dev/null
    . "${ENVDIR}/bin/activate"
    activated=1
  else
    echo "Warning: reusing virtualenv"
  fi
  echo -n "Running test suite against interpreter "
  "$1" --version

  pip install -q pytest

  find tests/ -name '*.pyc' -delete
  py.test -q tests/
  if [ "$activated" -eq 1 ]; then
    deactivate
  fi
}

# Make a best effort to run the tests against some Python version.
try_pip_tests() {
  if command -v "$1" &>/dev/null; then
    run_pip_tests "$1"
  fi
}

# Tests run when building RPMs are not allowed to use virtualenv.
run_rpm_tests() {
  py.test-2 tests/
  py.test-3 tests/
}

if [ $# -eq 0 ]; then
  try_pip_tests python2
  try_pip_tests python3
elif [ "$1" = "rpm" ]; then
  run_rpm_tests
else
  for py in "$@"; do
    run_pip_tests "$py"
  done
fi
