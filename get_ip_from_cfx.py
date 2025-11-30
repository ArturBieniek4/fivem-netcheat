import requests

def get_ip(cfx_id):
    data = requests.get(f"https://servers-frontend.fivem.net/api/servers/single/{cfx_id}")
    return data.json()['Data']['connectEndPoints'][0]

if __name__ == "__main__":
    import sys
    print(get_ip(sys.argv[1]))
