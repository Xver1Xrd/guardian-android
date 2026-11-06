#!/usr/bin/env bash
set -euo pipefail
adb_bin="${ANDROID_HOME:-$HOME/Android/Sdk}/platform-tools/adb"
device_id="${1:-emulator-5554}"
case "$device_id" in emulator-*) ;; *) echo 'Only an isolated emulator is accepted' >&2; exit 2;; esac
"$adb_bin" -s "$device_id" wait-for-device
if [[ "$("$adb_bin" -s "$device_id" shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ]]; then
  echo 'Device is not an emulator' >&2; exit 2
fi
booted=""
for _ in $(seq 1 120); do
  booted="$("$adb_bin" -s "$device_id" shell getprop sys.boot_completed | tr -d '\r')"
  [[ "$booted" == "1" ]] && break
  sleep 5
done
[[ "$booted" == "1" ]] || { echo 'Emulator did not finish booting' >&2; exit 2; }
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
installed=""
for _ in 1 2 3; do
  if "$adb_bin" -s "$device_id" install -r "$root_dir/app/build/outputs/apk/debug/app-debug.apk"; then
    installed="yes"
    break
  fi
  sleep 10
done
[[ "$installed" == "yes" ]] || { echo 'APK installation failed' >&2; exit 2; }
"$adb_bin" -s "$device_id" shell am start -n dev.guardian.app/.MainActivity
sleep 5
"$adb_bin" -s "$device_id" shell pidof dev.guardian.app
"$adb_bin" -s "$device_id" install -r "$root_dir/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
result="$("$adb_bin" -s "$device_id" shell am instrument -w dev.guardian.app.test/androidx.test.runner.AndroidJUnitRunner)"
printf '%s\n' "$result"
grep -q 'OK (1 test)' <<< "$result" || { echo 'Instrumentation did not pass' >&2; exit 1; }
