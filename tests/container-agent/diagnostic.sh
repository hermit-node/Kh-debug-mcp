#!/bin/sh
set -eu
printf 'USER_CONTAINER_SHELL_OK\n'
printf 'container_os=%s\n' "$(uname -s)"
test -r /agent/b-half.txt
printf 'B_HALF_PRESENT\n'
printf 'agent_role=%s\n' "$KH_AGENT_ROLE"
