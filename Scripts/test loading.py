
silence = True

import threading
import time

def my_task(callback):
    total_work_units = 5
    for i in range(total_work_units):
        time.sleep(0.1)
        callback((i+1) / total_work_units * 100)

def update_progress(progress_bar, progress):
    progress_bar[0] = progress
    progress_str = f"Progress: {int(progress)}% [{'=' * (int(progress) // 5)}{' ' * (20 - int(progress) // 5)}]"
    print(f"\r{progress_str}", end='', flush=True)

def main():
    if silence:
        print("executing in silence")
        progress_bar = [0]
        progress_thread = threading.Thread(target=update_progress, args=(progress_bar, 0))
        progress_thread.start()
        my_task(lambda p: update_progress(progress_bar, p))
        progress_thread.join()
        print("\nExecution finished.")
    else:
        print("executing in verbose")
        my_task(lambda p: None)
        print("execution finished.")


# main()


import threading
import time

def animate():
    while not done:
        for c in '|/-\\':
            print(f'\rProgress: {int(progress_value)}% [{"=" * int(progress_value // 5)}{" " * (20 - int(progress_value // 5))}] {c}', end='', flush=True)
            time.sleep(0.1)

done = False
progress_value = 0

# Start the animation thread
animation_thread = threading.Thread(target=animate)
animation_thread.start()

# Simulate some work
while progress_value <= 100:
    # Do some work
    time.sleep(0.1)
    progress_value += 1

done = True
animation_thread.join()





