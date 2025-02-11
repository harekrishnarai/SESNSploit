import json
import os

def save_state(state, filename='state.json'):
    with open(filename, 'w') as f:
        json.dump(state, f)

def load_state(filename='state.json'):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return None
