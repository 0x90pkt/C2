import scapy
from netfilterqueue import NetfilterQueue
import socket
import re


def add_rules():
    with open('add_rules.json', 'r') as file:
        rules = file.read()
    return rules


def load_ruleset(nft):
    try:
        data_structure = json.loads(NFTABLES_RULESET_JSON)
    except json.decoder.JSONDecodeError as e:
        print(f"ERROR: failed to decode JSON: {e}")
        exit(1)

    try:
        nft.json_validate(data_structure)
    except Exception as e:
        print(f"ERROR: failed validating JSON schema: {e}")
        exit(1)

    rc, output, error = nft.json_cmd(data_structure)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print(f"ERROR: running JSON cmd: {error}")
        exit(1)

    if len(output) != 0:
        # more error control?
        print(f"WARNING: output: {output}")


def get_ruleset(nft):
    rc, output, error = nft.cmd("list ruleset")
    if rc != 0:
        # do proper error handling here, exceptions etc
        print("ERROR: running cmd 'list ruleset'")
        print(error)
        exit(1)

    if len(output) == 0:
        # more error control
        print("ERROR: no output from libnftables")
        exit(0)

    data_structure = json.loads(output)

    try:
        nft.json_validate(data_structure)
    except Exception as e:
        print(f"ERROR: failed validating json schema: {e}")
        exit(1)

    return data_structure


def rule_has_counter(rule: dict):
    for expr in rule["expr"]:
        if expr.get("counter") is not None:
            return True
    return False


def search_rules_with_counter(data_structure: dict):
    ret = []
    for object in data_structure["nftables"]:
        rule = object.get("rule")
        if not rule:
            continue

        if not rule_has_counter(rule):
            continue

        # at this point, we know the rule has a counter expr
        ret.append(
            dict(
                family=rule["family"],
                table=rule["table"],
                chain=rule["chain"],
                handle=rule["handle"],
            )
        )

    return ret

def knock_and_respond(packet):
    print(f"{packet}\n\n")
    ogpkt = packet.get_payload()
    mark = packet.get_mark()
    pktid = packet.id()
    pkt = IP(packet.get_payload())
    print(f"{pkt}\n\n")
    packet.set_payload(str(pkt))
    if IP in pkt:
        ip_src = pkt[IP].src
    if UDP in pkt:
        dst_port = pkt[UDP].dport
    print(f'Source IP: {ip_src}\n '
          f'Destination Port: {dst_port}\n\n')
    send_port = "46290"
    message = mark + pktid
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        sock.sendto(bytes(message, "utf-8"), (ip_src, send_port))
        print("[*]Confirmation Packet sent.")
        sock.close()
    except Exception as e:
        print(f"ERROR: failed to sent packet: {e}")
        exit(1)
    packet.drop()
    return message


def knock2_and_shell(packet):
    print(f"{packet}\n\n")
    ogpkt = packet.get_payload()
    mark = packet.get_mark()
    pktid = packet.id()
    pkt = IP(packet.get_payload())
    print(f"{pkt}\n\n")
    packet.set_payload(str(pkt))
    if IP in pkt:
        ip_src = pkt[IP].src
    if UDP in pkt:
        dst_port = pkt[UDP].dport
    match = re.search(message, ogpkt)
    print(f'Source IP: {ip_src}\n '
          f'Destination Port: {dst_port}\n\n')
    print("Verifying connection...\n")
    if match:
        print(f"Messages match: {message} \nConnection confirmed!\nSending shell!")
    else:
        print("Messages don't match. Not sending shell.")
        exit(1)
    packet.drop()


def delete_rules(nft):
    # get the ruleset from the kernel, im JSON format and search for
    # all rules with a 'counter' expression on them, get their information
    kernel_ruleset = get_ruleset(nft)
    info_about_rules_to_delete = search_rules_with_counter(kernel_ruleset)

    # generate a new command to delete all interesting rules, validate and run it
    delete_rules_command = dict(nftables=[])
    delete_rules_command["nftables"] = []
    delete_rules_command["nftables"].append(dict(metainfo=dict(json_schema_version=1)))

    for rule_info in info_about_rules_to_delete:
        delete_rules_command["nftables"].append(dict(delete=dict(rule=rule_info)))

    try:
        nft.json_validate(delete_rules_command)
    except Exception as e:
        print(f"ERROR: failed validating JSON schema: {e}")
        exit(1)

    rc, output, error = nft.json_cmd(delete_rules_command)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print(f"ERROR: running JSON cmd: {error}")
        exit(1)

    if len(output) != 0:
        # more error control?
        print(f"WARNING: output: {output}")


# read in rules to listen for trigger packets
NFTABLES_RULESET_JSON = add_rules()


def main():
    nft = nftables.Nftables()
    nft.set_json_output(True)
    nft.set_handle_output(
        True
    )  # important! to get the rule handle when getting the ruleset
    # load the ruleset in JSON format into the kernel
    # see other examples in this tutorial to know more about how this works
    load_ruleset(nft)

    nfqueue = NetfilterQueue()
    message = nfqueue.bind(1, knock_and_respond)
    nfqueue.bind(2, knock2_and_shell(message))

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()
    delete_rules(nft)

    # ok!
    exit(0)


if __name__ == "__main__":
    main()

