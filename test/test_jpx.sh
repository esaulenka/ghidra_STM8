#!/bin/bash 
set -euxo pipefail

source common.sh
compile_and_decompile <<EOF
int test_function(void) {
  return 123;
}

int main(void) {
  volatile int(*function)(void) = test_function;
  function();
  return function();
}
EOF
