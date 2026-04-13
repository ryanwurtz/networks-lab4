from student.net_utils import send_dns_query, recv_dns_response

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
CLASS_IN = 1

# Your helper code goes here
def build_query(name: str):
    txid = 1
    flags = 0x0100
    qdcount = 1
    zeros = 0

    header = txid.to_bytes(2, byteorder='big') + flags.to_bytes(2, byteorder='big') + qdcount.to_bytes(2, byteorder='big') + zeros.to_bytes(6, byteorder='big')

    qname = b''
    for label in name.split('.'):
        qname += len(label).to_bytes(1, byteorder='big') + label.encode('ascii')
    qname += b'\x00'

    return header + qname + TYPE_A.to_bytes(2, byteorder='big') + CLASS_IN.to_bytes(2, byteorder='big')

def parse_name(packet: bytes, offset: int):
    labels = []
    while True:
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        labels.append(packet[offset+1 : offset+1+length].decode('ascii'))
        offset += 1 + length
    return ".".join(labels), offset

def parse_record(packet: bytes, offset: int):
    #record echo 
    name, offset = parse_name(packet, offset)
    rtype = int.from_bytes(packet[offset:offset+2], 'big')
    rclass = int.from_bytes(packet[offset+2:offset+4], 'big')

    #answer specific info
    ttl = int.from_bytes(packet[offset+4:offset+8], 'big')
    length = int.from_bytes(packet[offset+8:offset+10], 'big')
    offset += 10
    
    if rtype == TYPE_A:
        ip = ".".join(str(b) for b in packet[offset:offset+length])
    elif rtype in (TYPE_NS, TYPE_CNAME):
        ip, _ = parse_name(packet, offset)
    else:
        ip = packet[offset:offset+length]
        
    offset += length
    return {"name": name, "type": rtype, "ip": ip}, offset

def parse_packet(packet: bytes):
    #header parsing
    ancount = int.from_bytes(packet[6:8], byteorder='big')
    nscount = int.from_bytes(packet[8:10], byteorder='big')
    arcount = int.from_bytes(packet[10:12], byteorder='big')
    offset = 12

    #question echo
    _, offset = parse_name(packet, offset)
    offset += 4 #skip qtype and qclass
    
    #answer records
    answers = []
    for _ in range(ancount):
        answer, offset = parse_record(packet, offset)
        answers.append(answer)
        
    return answers

def recursive_resolve(name: str, recursive_server: str) -> str | None:
    sock = send_dns_query(recursive_server, build_query(name))
    response = recv_dns_response(sock)

    answers = parse_packet(response)

    #look for an A record first
    for answer in answers:
        if answer["type"] == TYPE_A:
            return answer["ip"]
    #if no A records, chase cname
    for answer in answers:
        if answer["type"] == TYPE_CNAME:
            return recursive_resolve(answer["ip"], recursive_server)
        
    return None