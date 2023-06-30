import socket
from datetime import datetime
import time
import numpy as np
import re
import struct
import matplotlib.pyplot as plt

plt.ion()
f, ax = plt.subplots()
f.show()
f.canvas.draw()
plot = ax.scatter([], [])


class PointCloudLMS:
    def __init__(
        self,
        ranges: np.ndarray,
        intensities: np.ndarray,
        start_angle: float,
        end_angle: float,
        ang_increment: float,
    ):
        self.ranges = ranges / 1000  # scanner delivers mm
        self.intensities = intensities
        self.start_angle = start_angle
        self.end_angle = end_angle
        self.ang_increment = ang_increment

        if ranges.size != intensities.size:
            raise ValueError("Ranges not same size as intensities")

        if ranges.size != 1 + (end_angle - start_angle) / ang_increment:
            raise ValueError("Mismatch between angles and ranges")

        angles = np.linspace(start_angle, end_angle, ranges.size) * np.pi / 180
        self.sin_map = np.sin(angles)
        self.cos_map = np.cos(angles)

    def cartesian_2d(self):
        return np.array([self.ranges * self.cos_map, self.ranges * self.sin_map])


def display_cloud(cloud: PointCloudLMS):

    global plot
    plot.remove()
    points = cloud.cartesian_2d()
    plot = ax.scatter(points[0, :], points[1, :], color="blue", marker=".")
    f.canvas.draw()
    f.canvas.flush_events()
    plt.pause(0.01)


def parse_int32(hex_string: bytes):
    return struct.unpack(">i", bytes.fromhex(hex_string.decode("ascii").zfill(8)))[0]


def parse_int16(hex_string: bytes):
    return struct.unpack(">h", bytes.fromhex(hex_string.decode("ascii").zfill(4)))[0]


def parse_scan_telegram(telegram: bytes):
    """Expects STX and ETX bytes to be stripped off"""

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
        values = np.array(values)
        angles = np.array(angles)
        return ang_incr, angles, values

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

    channels_16bit = [parse_channel(tokens) for i in range(num_16bit_channels)]

    num_8bit_channels = int(next(tokens), 16)
    channels_8bit = [parse_channel(tokens) for i in range(num_8bit_channels)]
    _, _, ranges = channels_16bit[0]
    ang_incr, angles, intensities = channels_8bit[0]

    position = int(next(tokens), 16)
    name = int(next(tokens), 16)
    if name == 1:
        next(tokens)
        next(tokens)

    comment = int(next(tokens), 16)
    time = int(next(tokens), 16)
    if time == 1:
        y = int(next(tokens), 16)
        mo = int(next(tokens), 16)
        d = int(next(tokens), 16)
        h = int(next(tokens), 16)
        mi = int(next(tokens), 16)
        s = int(next(tokens), 16)
        us = int(next(tokens), 16)
        date = datetime(y, mo, d, hour=h, minute=mi, second=s, microsecond=us)
        print(date)
    else:
        print("there is no time")

    return PointCloudLMS(ranges, intensities, angles[0], angles[-1], ang_incr)


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
    # buggy, this parses only error messages, no repsonses which might contain
    # success/failure messages.
    pattern = bytes("\x02sFA (.+)\x03", "ascii")
    match = re.search(pattern, response)
    if match:
        return int(match.group(1), 16)
    else:
        return 0


SCANNER_IP = "192.168.95.194"
SOPAS_PORT = 2111

scanner_sock = socket.create_connection((SCANNER_IP, SOPAS_PORT))


def send_command(cmd: str):
    cmd = cmd.encode("ascii")
    print(f"Sending {cmd}")
    scanner_sock.send(cmd)
    reply = scanner_sock.recv(4096)
    print(f"Response: {reply}")
    status = status_from_bytes(reply)
    errmsg = status_codes[status]
    print(errmsg)
    if errmsg != "Ok":
        raise ValueError(errmsg)
    return reply


def get_ip_address(dst_ip, dst_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dst_ip, dst_port))
    my_ip = s.getsockname()[0]
    s.close()
    return my_ip


def main():

    # put ntp server address here to get timestamps in the scan. dunno if they refer to
    # the measurement time or not
    my_ip = get_ip_address(SCANNER_IP, SOPAS_PORT)
    ip_hex_digits = [hex(int(f))[2:].upper() for f in my_ip.split(".")]

    accessmode_cmd = "\x02sMN SetAccessMode 03 F4724744\x03"
    send_command(accessmode_cmd)

    ntp_role_cmd = "\x02sWN TSCRole 1\x03"
    send_command(ntp_role_cmd)

    ntp_iface_cmd = "\x02sWN TSCTCInterface 0\x03"
    send_command(ntp_iface_cmd)

    ntp_server_cmd = "\x02sWN TSCTCSrvAddr " + " ".join(ip_hex_digits) + "\x03"
    send_command(ntp_server_cmd)

    set_scancfg_cmd = "\x02sMN mLMPsetscancfg +2500 +1 +1667 -50000 +1850000\x03"
    send_command(set_scancfg_cmd)

    set_scandatacfg_cmd = "\x02sWN LMDscandatacfg 00 00 1 0 0 0 00 0 0 0 1 +1\x03"
    reply = send_command(set_scandatacfg_cmd)

    set_echo_cmd = "\x02sWN FREchoFilter 2\x03"
    reply = send_command(set_echo_cmd)

    set_outputrange_cmd = "\x02sWN LMPoutputRange 1 +1667 -50000 +1850000\x03"
    reply = send_command(set_outputrange_cmd)

    storeparams_cmd = "\x02sMN mEEwriteall\x03"
    reply = send_command(storeparams_cmd)

    get_params_cmd = "\x02sRN LMPscancfg\x03"
    reply = send_command(get_params_cmd)

    run_cmd = "\x02sMN Run\x03"
    reply = send_command(run_cmd)
    # stop_cmd = "\x02sMN LMCstopmeas\x03"
    # reply = send_command(stop_cmd)

    # senddata_cmd = "\x02sEN LMDscandata 1\x03"
    # reply = send_command(senddata_cmd)
    # partial_datagrams = list()
    # t = time.time()
    # c = 0
    # try:
    #     while True:
    #         data = scanner_sock.recv(2 * 4096)
    #         etx_idx = data.find(b"\x03")
    #         if etx_idx >= 0:
    #             partial_datagrams.append(data[: etx_idx + 1])
    #             complete_data = b"".join(partial_datagrams)
    #             c += 1
    #             # print("Got complete datagram ", complete_data)
    #             t1 = time.time()
    #             # print(f"Hz: {c / (t1-t)}")
    #             cloud = parse_scan_telegram(complete_data[1:-2])
    #             if c % 2 == 0:
    #                 display_cloud(cloud)
    #             partial_datagrams = list()
    #             partial_datagrams.append(data[etx_idx + 1 :])
    #         else:
    #             partial_datagrams.append(data)
    #         # print(f"Received data of size {len(data)}: ", data)

    # except:
    #     stop_cmd = "\x02sMN LMCstopmeas\x03"
    #     reply = send_command(stop_cmd)


if __name__ == "__main__":
    main()
