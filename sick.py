import socket
import re
import struct


def parse_int32(hex_string: bytes):
    return struct.unpack(">i", bytes.fromhex(hex_string.decode('ascii').zfill(8)))[0]

def parse_int16(hex_string: bytes):
    return struct.unpack(">h", bytes.fromhex(hex_string.decode('ascii').zfill(4)))[0]


def parse_scan_telegram(telegram: bytes):
    """Expects STX and ETX bytes to be stripped off"""
    tokens = (t for t in telegram.split(b" "))
    method = next(tokens)
    command = next(tokens)
    proto_version = next(tokens)
    device_num = next(tokens)
    serial_num = int(next(tokens), 16)
    device_status = (next(tokens), next(tokens))
    num_telegrams = next(tokens)
    num_scans = next(tokens)
    time_since_boot_us = int(next(tokens), 16)
    time_of_transmission_us = int(next(tokens), 16)
    status_digital_input_pins = (next(tokens), next(tokens))
    status_digital_output_pins = (next(tokens), next(tokens))
    layer_angle = next(tokens)  # should be 0
    scan_freq = int(next(tokens), 16) / 100
    measurement_freq = int(next(tokens), 16)  # should be 1141 * 25
    encoder = int(next(tokens), 16)
    if encoder != 0:
        encoder_pos = next(tokens)
        encoder_speed = next(tokens)
    num_16bit_channels = int(next(tokens), 16)

    def parse_channel(generator):
        content = next(tokens)
        scale_factor = int(next(tokens), 16)
        if scale_factor == int("3F800000", 16):
            scale_factor = 1
        elif scale_factor == int("40000000", 16):
            scale_factor = 2
        else:
            raise ValueError(f"Unexpected scale factor {scale_factor}")

        offset = int(next(tokens), 16)
        start_angle_hex = next(tokens)
        start_angle = parse_int32(start_angle_hex) / 10000

        ang_incr_hex = next(tokens)
        ang_incr = parse_int16(ang_incr_hex) / 10000
        n_data = int(next(tokens), 16)
        values = [offset + scale_factor * int(next(tokens), 16) for i in range(n_data)]
        angles = [start_angle + i * ang_incr for i in range(n_data)]
        return angles, values

    channels_16bit = [parse_channel(tokens) for i in range(num_16bit_channels)]

    num_8bit_channels = int(next(tokens), 16)
    channels_8bit = [parse_channel(tokens) for i in range(num_8bit_channels)]

    __import__("ipdb").set_trace()


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

    set_echo_cmd = "\x02sWN FREchoFilter 2\x03"
    print(set_echo_cmd.encode("ascii"))
    reply = send_command(set_echo_cmd)
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
    partial_datagrams = list()
    while True:
        data = scanner_sock.recv(2 * 4096)
        etx_idx = data.find(b"\x03")
        if etx_idx >= 0:
            partial_datagrams.append(data[: etx_idx + 1])
            complete_data = b"".join(partial_datagrams)
            print("Got complete datagram ", complete_data)
            parse_scan_telegram(complete_data[1:-2])
            partial_datagrams = list()
            partial_datagrams.append(data[etx_idx + 1 :])
        else:
            partial_datagrams.append(data)
        print(f"Received data of size {len(data)}: ", data)


if __name__ == "__main__":
    main()
    # example_response = (b"\x02sSN LMDscandata 0 1 1374C54 0 0 0 3F0E 2BF460C 2BFE48F 0"
    # b" 0 3F 0 0 9C4 21C 0 1 DIST1 3F800000 00000000 FFFF3CB0 683 475 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 16F 186 19C"
    # b" 1AB 1B6 1C4 1C3 1BC 1CB 1CF 1CD 1D0 1CC 1D1 1D4 1CD 1D0 1D8 1D2 1DC 1E0 1E0 1E7 1E1"
    # b" 1E5 1E9 1EE 1ED 1EF 1EC 1EB 1E7 1E6 1E6 1E4 1EB 1E4 1E1 1E0 1E0 1EA 1F4 1F1 1F6 1F6"
    # b" 1F9 1F9 1FF 1FA 1F7 1FD 1FE 1F9 1FF 1F4 1FE 1FD 202 1FB 200 1FA 202 1FE 202 202 201"
    # b" 202 1FB 205 202 207 208 205 207 210 203 208 200 1FF 1F7 1EE 1EC 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 43E 433 43A"
    # b" 43B 436 432 42C 424 428 42B 428 429 431 433 434 438 435 43F 43A 43C 43E 446 445 44A"
    # b" 44A 44A 457 453 45B 452 455 461 459 460 462 46B 46A 469 471 476 476 475 47 A 485 47D"
    # b" 485 487 48C 496 495 498 4A1 4A5 49E 4A1 4AB 4A8 4B0 4B7 4BA 4BE 4BF 4C7 4C5 4CB 4D8"
    # b" 4DB 4D6 4DB 4E6 4E9 4ED 4F1 4F0 4FB 4F4 4FB 504 507 50C 518 518 51A 524 52A 52A 533"
    # b" 538 539 53E 546 54E 54C 557 559 562 56A 56D 573 574 57E 580 589 585 596 599 59E 5A9"
    # b" 5A7 5B1 5B7 5B8 5C6 5CC 5CD 5DA 5E3 5E4 5EB 5F7 5F4 602 609 60A 615 624 61D 62B 632"
    # b" 63E 645 64E 655 659 668 66C 673 68 0 68B 68D 699 6A3 6AD 6BA 6BB 6C7 6D2 6DC 6E8 6F1"
    # b" 700 701 70F 718 724 72E 739 746 74C 753 768 76F 77D 785 78F 791 789 789 78A 789 788"
    # b" 787 780 77D 780 77B 773 77A 770 771 771 767 768 75F 762 75B 762 75B 759 759 75C 756"
    # b" 755 750 74D 74C 744 748 748 748 744 742 73C 73D 73B 73E 73A 73B 72F 726 72B 724 71D"
    # b" 714 720 711 715 71B 71B 718 717 70F 70E 70C 70E 70B 70D 704 70E 711 710 707 70 5 705"
    # b" 706 703 6FE 6F8 702 6FC 6FB 6FA 6FA 6FC 6F9 6EA 6F0 6EB 6F0 6EF 6F5 6F0 6EF 6ED 6E9"
    # b" 6EF 6EE 6F0 6E9 6E8 6EA 6E8 6E8 6E3 6DF 6E1 6E0 6DF 6DF 6E2 6DC 6DE 6D4 6DA 6E1 6E2"
    # b" 6DC 6D7 6D6 6DB 6D8 6D9 6CF 6D8 6D7 6D7 6D5 6D6 6D4 6D5 6D4 6D7 6D3 6D0 6D1 6CD 6CE"
    # b" 6CE 6CE 6C9 6CD 6CF 6C9 6C8 6C5 6CF 6CB 6C8 6CA 6C7 6C6 6D1 6CB 6C9 6D4 6C9 6C9 6CA"
    # b" 6CC 6C8 6CB 6C5 6CA 6C3 6C9 6C6 6D0 6C C 6CE 6CC 6C9 6CD 6CA 6D1 6CE 6CE 6CE 1 RSSI1"
    # b" 3F800000 00000000 FFFF3CB0 683 475 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 7D 86 90 A4 AA B5 B4 B4 B2 B5 B6 B9 BB C0"
    # b" C3 CB CF D1 D6 D7 DA DA DA D8 DD D9 DD DB D8 D7 D6 D3 D1 CD C8 C4 C3 C1 BF C4 C8 CB"
    # b" D1 D5 D6 DA DB DB D9 D9 DA DA D8 D8 D5 D7 D6 D7 D6 D6 D4 D8 D5 D6 D6 D5 D4 D4 D4 D1"
    # b" CF CC C2 C0 B9 B0 A6 97 81 68 54 43 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    # b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 82 8F 8D 96 9B A8 AF AF BA BC C0 C2 C4"
    # b" C6 CB CE CC CE D0 D0 D1 D4 D4 D3 D5 D5 D6 D6 D9 D6 D8 D9 D9 DB DD DC DD DE E0 E1 E1"
    # b" E0 E4 E7 E2 E5 E3 E4 E7 E8 E1 E6 E7 E2 E3 E3 E5 E3 E7 E2 E7 E7 E3 E2 E4 E4 E3 E0 E2"
    # b" E3 E6 E3 E3 DF E2 E3 E2 E2 E2 E0 E2 E3 E3 E3 E3 E2 E5 E4 E3 E0 E3 E3 E2 DF E1 E0 E2"
    # b" E3 E0 DF E2 E1 DE DD DD DB E0 DE DC DD DB DB DE DB DB DD DB DB DA D9 D8 DA D8 D8 D9"
    # b" D8 D6 D7 D6 D8 D7 D7 D8 D8 D8 D9 D7 D9 D9 D9 D8 D9 DA D9 D8 D9 DA D8 DA DB D9 D7 D8"
    # b" D9 D8 D8 D8 D5 D7 D3 D3 D4 D5 D6 DE E3 E2 DD DE DF DD DE DC DB D9 DA DB DB DA DE DD"
    # b" DC DF DD E1 E3 E4 E3 E4 E3 E6 E6 EB E6 E8 E9 EA EA EF ED EA EF EA EB E5 DF D4 A2 67"
    # b" 77 65 71 6A 4D 49 48 47 4A 4A 4B 4F 4D 4D 50 51 56 5F 5B 5A 5E 5F 59 59 58 59 5E 5F"
    # b" 66 66 68 68 68 67 6B 6B 6F 6A 72 73 75 71 77 7B 79 7D 7F 7D 7D 81 7F 84 84 86 87 8A"
    # b" 8A 8C 8D 8D 91 93 94 95 96 9B 9F 9F A3 A6 A6 A6 AA AB AB AD AF B0 B5 B6 B9 BD C2 C4"
    # b" C7 CC CD D1 D5 D7 D9 DB DE E0 E4 E7 EB F2 F9 FE FE FE FE FE FE FE FE FE FE FE FE FE"
    # b" FE FE F7 F1 EB EA E4 E1 DC DA D8 D3 D2 D0 CE CC 0 0 0 1 7B2 1 1B 11 33 39 1D8A8"
    # b" 0\x03")
    # parse_scan_telegram(example_response[1:-2])
