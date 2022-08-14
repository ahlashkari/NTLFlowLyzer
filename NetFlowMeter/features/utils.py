#!/usr/bin/env python3


def calculate_flow_payload_bytes(flow):
    total_bytes = [packet.get_payloadbytes() for packet in flow.get_packets()]
    return sum(total_bytes)


def calculate_fwd_flow_payload_bytes(flow):
    total_bytes = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
    return sum(total_bytes)


def calculate_bwd_flow_payload_bytes(flow):
    total_bytes = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
    return sum(total_bytes)
