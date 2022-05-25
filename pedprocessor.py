# -*- coding: utf-8 -*-

import socket
import traceback
from logging import Logger
from typing import Optional

from systools import sys_log_exception, sys_log_info


class PedProcessor(object):

    def __init__(self, local_logger: Logger, service_name: str, tcp_ip: str, tpc_port: int) -> None:

        self.local_logger = local_logger
        self.service_name = service_name
        self.tcp_ip = tcp_ip
        self.tcp_port = tpc_port
        self.identifier_version = b"V2"
        self.connection_timeout = 10

    def open_socket(self, timeout: Optional[int] = 10) -> socket:
        ped_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            ped_socket.settimeout(self.connection_timeout)
        ped_socket.connect((self.tcp_ip, self.tcp_port))
        if timeout:
            ped_socket.settimeout(None)

        sys_log_info(f"[{self.service_name}] Connected on [{self.tcp_ip}:{self.tcp_port}]")

        return ped_socket

    def close_socket(self, ped_socket: socket) -> None:
        if ped_socket:
            ped_socket.close()
            sys_log_info(f"[{self.service_name}] Connection closed")

    def send_message(self, params: list, ped_socket: socket, wait_response: bool = True) -> Optional[bytes]:
        try:
            payload = b",".join([str.encode(x) for x in params])

            self.local_logger.info(f"POS input: {payload}")

            length = len(payload).to_bytes(2, byteorder="big")
            lrc = payload[0]
            for b in payload[1:]:
                lrc ^= b
            lrc = lrc.to_bytes(1, byteorder="big")

            data = self.identifier_version + length + payload + lrc
            ped_socket.send(data)

            if not wait_response:
                return

            received_data = ped_socket.recv(4)[2:]
            response_length = int.from_bytes(received_data, byteorder="big")

            remaining_data = ped_socket.recv(response_length + 1)
            validator_lrc = remaining_data[-1]

            lrc = 0
            for b in remaining_data[:-1]:
                lrc ^= b

            if validator_lrc != lrc:
                raise InvalidLrc("Invalid lrc parsing output message")

            response = remaining_data[:-1]

            self.local_logger.info(f"PED output: {response}")

            return response

        except Exception as ex:
            sys_log_exception(traceback.format_exc())
            self.local_logger.exception(f"Cannot send PED message: {traceback.format_exc()}")
            if ped_socket:
                ped_socket.close()
            raise ex


class InvalidLrc(Exception):
    pass
