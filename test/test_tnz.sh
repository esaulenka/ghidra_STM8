#!/bin/bash 
set -euxo pipefail

source common.sh
compile_and_decompile <<EOF
char test_function(void) {
  return 1;
}

int main(void) {
  if (test_function() == 0) {
    return 0;
  }
  return 1;
}
EOF
