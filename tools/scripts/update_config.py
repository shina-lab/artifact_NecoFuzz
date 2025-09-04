import yaml
import sys

def load_config(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def save_config(data, file_path):
    with open(file_path, 'w') as file:
        yaml.dump(data, file, default_flow_style=False, sort_keys=False)

def update_config_value(config, key1, key2, new_value):
    if key1 in config and key2 in config[key1]:
        config[key1][key2] = new_value
    else:
        raise KeyError(f"Keys {key1}/{key2} not found in the config")

def main():
    if len(sys.argv) != 5:
        print("Usage: update_config.py <config_file> <key1> <key2> <new_value>")
        sys.exit(1)

    config_file, key1, key2, new_value = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    config_data = load_config(config_file)

    try:
        update_config_value(config_data, key1, key2, new_value)
    except KeyError as e:
        print(e)
        sys.exit(1)

    save_config(config_data, config_file)

if __name__ == "__main__":
    main()
