#!/bin/sh
set -eu
printf 'USER_CONTAINER_SHELL_OK\n'
printf 'container_os=%s\n' "$(uname -s)"
test -r /agent/B.png
printf 'B_IMAGE_PRESENT\n'
printf 'agent_role=%s\n' "$KH_AGENT_ROLE"
