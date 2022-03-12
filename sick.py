import socket
import re

status_codes = [
    "Ok",
    "Sopas_Error_METHODIN_ACCESSDENIED",
    "Sopas_Error_METHODIN_UNKNOWNINDEX",
    "Sopas_Error_VARIABLE_UNKNOWNINDEX",
    "Sopas_Error_LOCALCONDITIONFAILED",
    "Sopas_Error_INVALID_DATA",
    "Sopas_Error_UNKNOWN_ERROR",
    "Sopas_Error_BUFFER_OVERFLOW",
    "Sopas_Error_BUFFER_UNDERFLOW",
    "Sopas_Error_ERROR_UNKNOWN_TYPE",
    "Sopas_Error_VARIABLE_WRITE_ACCESSDENIED",
    "Sopas_Error_UNKNOWN_CMD_FOR_NAMESERVER",
    "Sopas_Error_UNKNOWN_COLA_COMMAND",
    "Sopas_Error_METHODIN_SERVER_BUSY",
    "Sopas_Error_FLEX_OUT_OF_BOUNDS",
    "Sopas_Error_EVENTREG_UNKNOWNINDEX",
    "Sopas_Error_COLA_A_VALUE_OVERFLOW",
    "Sopas_Error_COLA_A_INVALID_CHARACTER",
    "Sopas_Error_OSAI_NO_MESSAGE",
    "Sopas_Error_OSAI_NO_ANSWER_MESSAGE",
    "Sopas_Error_INTERNAL",
    "Sopas_Error_HubAddressCorrupted",
    "Sopas_Error_HubAddressDecoding",
    "Sopas_Error_HubAddressAddressExceeded",
    "Sopas_Error_HubAddressBlankExpected",
    "Sopas_Error_AsyncMethodsAreSuppressed",
    "Sopas_Error_ComplexArraysNotSupported",
]


def status_from_bytes(response: bytes):
    pattern = bytes("\x02sFA (.+)\03", "ascii")
    match = re.search(pattern, response)
    if match:
        return int(match.group(1), 16)
    else:
        return 0


scanner_sock = socket.create_connection(("192.168.95.194", 2111))


def send_command(cmd: str):
    scanner_sock.send(cmd.encode("ascii"))
    return scanner_sock.recv(4096)


def main():
    accessmode_cmd = "\x02sMN SetAccessMode 03 F4724744\x03"
    print(send_command(accessmode_cmd))

    set_scancfg_cmd = "\x02sMN mLMPsetscancfg +2500 +1 +1667 -50000 +1850000\x03"
    print(send_command(set_scancfg_cmd))

    set_scandatacfg_cmd = "\x02sWN LMDscandatacfg 00 00 1 0 0 0 00 0 0 0 1 +1\x03"
    print(set_scandatacfg_cmd.encode("ascii"))
    reply = send_command(set_scandatacfg_cmd)
    print(reply)
    status = status_from_bytes(reply)
    print(status_codes[status])

    set_outputrange_cmd = "\x02sWN LMPoutputRange 1 +1667 -50000 +1850000\x03"
    print(set_outputrange_cmd.encode("ascii"))
    reply = send_command(set_outputrange_cmd)
    print(reply)
    status = status_from_bytes(reply)
    print(status_codes[status])

    storeparams_cmd = "\x02sMN mEEwriteall\x03"
    print(storeparams_cmd.encode("ascii"))
    reply = send_command(storeparams_cmd)
    print(reply)
    status = status_from_bytes(reply)
    print(status_codes[status])

    run_cmd = "\x02sMN Run\x03"
    print(run_cmd.encode("ascii"))
    reply = send_command(run_cmd)
    print(reply)
    status = status_from_bytes(reply)
    print(status_codes[status])

    senddata_cmd = "\x02sEN LMDscandata 1\x03"
    print(senddata_cmd.encode("ascii"))
    reply = send_command(senddata_cmd)
    print(reply)
    status = status_from_bytes(reply)
    print(status_codes[status])
    data = scanner_sock.recv(4096)
    print(data)

if __name__ == "__main__":
    main()
