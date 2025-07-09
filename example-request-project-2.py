import requests
import json

URL = "http://127.0.0.1:5000/test_get/15"
numbers = "3452"
PARAMS = {'numbers':numbers, 'dict_ex': json.dumps({'tag1': 1, 'tag2': 2})}
r = requests.get(url = URL, params = PARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqYW1lcy5tYXJpYW5pIiwgImFjY2VzcyI6ICJUcnVlIn0=.e4d6e529e675f2bdd363da4c50219317375b7cc7d49da91083d1f0f09044ff89'})
#r = requests.post(url = URL, data = PARAMS)
data = r.json()
print(data)