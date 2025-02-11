import time

def loading_animation():
    animations = ['[■□□□□□□□□□]', '[■■□□□□□□□□]', '[■■■□□□□□□□]', '[■■■■□□□□□□]', '[■■■■■□□□□□]', '[■■■■■■□□□□]', '[■■■■■■■□□□]', '[■■■■■■■■□□]', '[■■■■■■■■■□]', '[■■■■■■■■■■]']
    for i in range(20):
        print(f"\r{animations[i % len(animations)]}", end='', flush=True)
        time.sleep(0.1)
