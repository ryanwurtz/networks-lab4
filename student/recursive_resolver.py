from student.net_utils import send_dns_query, recv_dns_response

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
CLASS_IN = 1


# Your helper code goes here




def recursive_resolve(name: str, recursive_server: str) -> str | None:
    raise NotImplementedError