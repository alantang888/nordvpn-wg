import requests
import random
import base64

WG_CONFIG_TEMPLATE = '''
[Interface]
PrivateKey={}
Address={}
DNS=1.1.1.1

[Peer]
PublicKey={}
AllowedIPs=0.0.0.0/0
Endpoint={}
PersistentKeepalive=25
'''

def get_private_key(token):
    token_encoded = base64.b64encode(f'token:{token}'.encode()).decode()
    headers = {'Authorization': f'Basic {token_encoded}'}
    key_response = requests.get("https://api.nordvpn.com/v1/users/services/credentials", headers=headers)
    if key_response.status_code != 200:
        return None
    return key_response.json()['nordlynx_private_key']

def get_servers(city_code):
    # get country and city code on https://api.nordvpn.com/v1/servers/countries
    # filters[servers_groups]=11 => Standard_VPN_Servers
    # more filter can reference https://github.com/NordSecurity/nordvpn-linux/blob/main/core/urls.go
    url = f"https://api.nordvpn.com/v1/servers?limit=7000&filters[country_city_id]={city_code}&filters[servers_technologies][identifier]=wireguard_udp"
    server_response = requests.get(url)
    if server_response.status_code != 200:
        return None
    return sorted(server_response.json(), key=lambda x: x['load'])

def get_wg_config(token, city_code, random_low_load_server=100):
    private_key = get_private_key(token)
    servers = get_servers(city_code)
    server = random.choice(servers[0:random_low_load_server])
    
    # Look like this is hardcode on nordvpn client too
    server_port = 51820
    peer_ip_address = '10.5.0.2'
    
    # Just assume that exist. So not handling exception as lazy
    server_wg_metadata = [t for t in server['technologies'] if t['identifier'] == 'wireguard_udp'][0]['metadata']
    server_wg_public_key = [m['value'] for m in server_wg_metadata if m['name'] == 'public_key'][0]
    
    # server_ip, server_port, server_key, private_key, peer_ip
    return server['hostname'], server_port, server_wg_public_key, private_key, peer_ip_address

def main():
    token = input('NordVPN Token: ')
    city_code = input('Country code can get from https://api.nordvpn.com/v1/servers/countries\nCountry code: ')
    server_ip, server_port, server_key, private_key, peer_ip = get_wg_config(token, city_code)
    if private_key is None:
        private_key = 'CHANGE_ME'
    
    print('Your Wireguard config:')
    print(WG_CONFIG_TEMPLATE.format(private_key, peer_ip, server_key, f'{server_ip}:{server_port}'))
    

if __name__ == '__main__':
    main()
