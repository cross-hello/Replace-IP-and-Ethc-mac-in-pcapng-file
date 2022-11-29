# Remove physical info from pcapng file

Replace ip, mac, dns domain of server to another one so you could share packet publicly to analyze.

### Usage

Install pip package first:

`pip install -r requirement`

```python
import replace_data_in_pcapng as rp
server_ip='4.4.4.4'#specify your server ip
server_domain='server'#specify your server domain name
server_mac='33:33:33:33:33:33'#specify your server mac(Optional) 
ip_tag=[]
ip_tag.append((server_ip,'7.7.7.7'))
dns_tag=[]
dns_tag.append((server_domain,'server_replace_domain'))
#Replace DNS request for server domain name to the name 
mac_tag=[]
mac_tag.append((server_mac,'00:00:00:00:00:00'))
pcapng_file_name='abc.pcapng'
rp.replace_pcap(pcapng_file_name, ip_tag,dns_tag,mac_tag)
```

### Result


