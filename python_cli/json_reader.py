import json
import os


class JSONReader:
    @staticmethod
    def read_json():
        if os.path.exists("userdata.json"):
            with open("userdata.json", "r") as file:
                return json.load(file)
        else:
            return None