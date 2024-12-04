#!/bin/bash -e
# Copyright (C) 2021 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ROOT_DIR=$($(dirname $(dirname $(readlink -f "$0")))/gettop.sh)




#oplus edit to let bazel build at a fixed top dir,using namespace mount
OPLUS_REMOTE_CACHE_ONLY_SERVER="bazel-remote-cache.myoas.com"
# (tail '/')
TOP_DIR="$(realpath $ROOT_DIR/../)/"
#add TOP_DIR to update project.list ('repo list -f')
function get_cache_server_ip() {
 ip_array=($(/usr/bin/getent hosts $OPLUS_REMOTE_CACHE_ONLY_SERVER |sort| awk '{print $1}'))
 size=${#ip_array[@]}
 index=$(( $((RANDOM)) % $size ))
 echo "${ip_array[$index]}"
}

if [[ "$OPLUS_USE_JFROG_CACHE" == "true" || "$OPLUS_USE_BUILDBUDDY_REMOTE_BUILD" == "true" ]];then
  tmp_hosts_file="$TOP_DIR/tmp_hosts"
  if [[ ! -e "$tmp_hosts_file" ]]; then
    cp /etc/hosts $tmp_hosts_file
    echo $(get_cache_server_ip 2>/dev/null) $OPLUS_REMOTE_CACHE_ONLY_SERVER >> $tmp_hosts_file
  fi

  # string A - string B (no head '/')
  sub_dir="${ROOT_DIR//$TOP_DIR}"
  mount_dir=/mnt
  py3_path="prebuilts/build-tools/path/linux-x86/python3"
  py_path=$(echo $(dirname $(readlink -f $0))/bazel.py | sed "s#${TOP_DIR}${sub_dir}/##" )
  new_root_dir="${mount_dir}/${sub_dir}"

  new_array=()
  # Loop through each element in $@
  for arg in "$@"; do
    if [[ $arg =~ $TOP_DIR ]]; then
      modified_arg=$(echo "$arg" | sed "s#${TOP_DIR}#${mount_dir}/#")
      new_array+=("$modified_arg")
    else
      new_array+=("$arg")
    fi
  done
  #add env -i to filter-out outside env values
  inner_cmd=('env' '-i' \
             "TOP_DIR=$mount_dir/" \
             "OPLUS_USE_JFROG_CACHE=$OPLUS_USE_JFROG_CACHE" \
             "OPLUS_USE_BUILDBUDDY_REMOTE_BUILD=$OPLUS_USE_BUILDBUDDY_REMOTE_BUILD" \
             'bash' '-c' '$0;$1;$2;$3;$4;"${@:5}"' \
               "/bin/mount -t tmpfs none /"  \
               "/bin/mount ${TOP_DIR} ${mount_dir} --bind" \
               "/bin/mount $tmp_hosts_file /etc/hosts --bind" \
               "cd ${mount_dir}/${sub_dir}" \
               "exec" "$py3_path" "$py_path" "$new_root_dir" "${new_array[@]}")
  extra_param=""
  if [[ "$(id -u)" != "0" ]];then
    extra_param="--map-root-user"
  fi
  #add a global fail retry
  /usr/bin/unshare $extra_param -m "${inner_cmd[@]}" \
   || OPLUS_USE_BUILDBUDDY_REMOTE_BUILD="false" OPLUS_USE_JFROG_CACHE="false" /usr/bin/unshare $extra_param -m "${inner_cmd[@]}"
else
  TOP_DIR=$TOP_DIR exec "$ROOT_DIR"/prebuilts/build-tools/path/linux-x86/python3 $(dirname $(readlink -f "$0"))/bazel.py "$ROOT_DIR" "$@"
fi
