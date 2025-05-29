import requests

def enviar_vector():
    data = {
            "data": [0] * 41,
            "ip": "192.168.1.101"
    }
    r = requests.post("http://localhost:5000/analizar", json=data)
    print(r.json())

if __name__=="__main__":
    enviar_vector()
