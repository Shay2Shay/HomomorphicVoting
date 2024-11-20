import json

def strToJSON(msg:str):
    return json.loads(msg)

def loadJSON(path: str) -> dict:
    with open(path, 'r') as f:
        data = json.load(f)
    return data

def saveJSON(jsn: dict, path='test.json') -> None:
    json_object = json.dumps(jsn, indent=4)
    with open(path, "w") as outfile:
        outfile.write(json_object)
    return

if __name__ == '__main__':
    print(loadJSON('test.json'))
    saveJSON({}, 'test.json')