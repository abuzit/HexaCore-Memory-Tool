import subprocess
import time


def find_pids_by_name(process_name):
  """Finds all PIDs matching the process name using tasklist, handling spaces."""
  pids = []
  try:
    output = subprocess.check_output(
        f'tasklist /fi "imagename eq {process_name}" /fo csv /nh',
        shell=True,
        text=True,
    )
    lines = output.strip().split("\n")
    for line in lines:
      if not line.strip() or "INFO:" in line:
        continue
      parts = line.split('","')
      if len(parts) >= 2:
        name_part = parts[0].strip('"')
        pid_str = parts[1].strip('"')
        if name_part.lower() == process_name.lower() and pid_str.isdigit():
          pids.append(int(pid_str))
  except Exception:
    pass
  return pids


def main():
  print("=== Process PID Finder ===")
  process_name = input(
      "Enter target process name (e.g., game.exe if you dont know you can just look in task manager): "
  ).strip()

  if not process_name:
    print("[-] Process name cannot be empty!")
    return

  search_name = (
      process_name
      if process_name.lower().endswith(".exe")
      else process_name + ".exe"
  )

  print(f"[*] Searching for '{search_name}'...")

  pids = find_pids_by_name(search_name)

  if pids:
    print(f"[+] Process is running! Found PID(s): {pids}")
  else:
    print("[-] Process is NOT running.")

  print("\n[+] Done. Press Enter to exit.")
  input()


if __name__ == "__main__":
  main()