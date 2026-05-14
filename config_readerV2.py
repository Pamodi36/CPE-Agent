import json
import requests


class ConfigReader:
    def __init__(self):
        # Fixed RESTCONF URL for the top-level "sdwan" container in Clixon datastore
        self.url = "http://127.0.0.1:8383/restconf/data/sdwan-cpe:sdwan"

        # Ask Clixon to return YANG JSON
        self.headers = {
            "Accept": "application/yang-data+json"
        }

    def get_intended_config(self):
        # Send HTTP GET request to Clixon RESTCONF
        response = requests.get(self.url, headers=self.headers, timeout=5)

        # Raise error for HTTP failures, for example 404 or 500
        response.raise_for_status()

        # Convert JSON response to Python dictionary
        data = response.json()

        # Check expected top-level key
        if "sdwan-cpe:sdwan" not in data:
            raise ValueError("Expected key 'sdwan-cpe:sdwan' not found in RESTCONF response")

        # Return only the inner sdwan container
        return data["sdwan-cpe:sdwan"]


if __name__ == "__main__":
    reader = ConfigReader()

    try:
        config = reader.get_intended_config()

        print("\nFull intended config:")
        print(json.dumps(config, indent=2))

    except Exception as e:
        print("Error reading config:", e)
