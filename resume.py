import psutil
import time

while True:
    # get all the running processes
    for proc in psutil.process_iter(['pid', 'name', 'status']):
        try:
            # check if the process is stopped
            if proc.status() == psutil.STATUS_STOPPED:
                # check if the process name should be skipped
                if proc.name() == "fileless-xec":
                    print("Skipping process", proc.pid, proc.name())
                else:
                    # resume the process
                    proc.resume()
                    print("Resumed process", proc.pid, proc.name())
        except psutil.NoSuchProcess:
            # the process may have terminated, ignore
            pass
    time.sleep(1)
    