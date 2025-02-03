import uuid
import subprocess
import hashlib


def get_mac_address():
    """获取设备的 MAC 地址"""
    mac = hex(uuid.getnode()).replace("0x", "").upper()
    mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


def get_disk_serial_number():
    """获取硬盘序列号 (仅限 Windows)"""
    try:
        output = subprocess.check_output("wmic diskdrive get serialnumber", shell=True)
        serial = output.decode().split("\n")[1].strip()
        return serial if serial else "UNKNOWN_DISK_SERIAL"
    except Exception as e:
        return f"ERROR: {e}"


def get_cpu_serial_number():
    """获取 CPU 序列号 (仅限 Windows)"""
    try:
        output = subprocess.check_output("wmic cpu get processorid", shell=True)
        serial = output.decode().split("\n")[1].strip()
        return serial if serial else "UNKNOWN_CPU_SERIAL"
    except Exception as e:
        return f"ERROR: {e}"


def get_device_uuid():
    """获取设备的 UUID (仅限 Windows)"""
    try:
        output = subprocess.check_output("wmic csproduct get uuid", shell=True)
        uuid_value = output.decode().split("\n")[1].strip()
        return uuid_value if uuid_value else "UNKNOWN_UUID"
    except Exception as e:
        return f"ERROR: {e}"


def compress_sequence_hash(sequence):
    """使用 SHA-256 哈希算法压缩序列码"""
    hash_object = hashlib.sha256(sequence.encode('utf-8'))
    return hash_object.hexdigest()


def generate_special_sequence():
    """生成特殊序列码，并使用哈希压缩"""
    mac = get_mac_address()
    disk_serial = get_disk_serial_number()
    cpu_serial = get_cpu_serial_number()
    device_uuid = get_device_uuid()

    # 按顺序拼接生成原始特殊序列码
    original_sequence = f"{mac}+{device_uuid}+{cpu_serial}+{disk_serial}"
    
    # 使用哈希算法压缩序列码
    compressed_sequence = compress_sequence_hash(original_sequence)

    return original_sequence, compressed_sequence


if __name__ == "__main__":
    print("获取设备信息中...")
    mac_address = get_mac_address()
    disk_serial = get_disk_serial_number()
    cpu_serial = get_cpu_serial_number()
    device_uuid = get_device_uuid()

    # 生成特殊序列码
    original_sequence, compressed_sequence = generate_special_sequence()
    
    print(f"MAC 地址: {mac_address}")
    print(f"硬盘序列号: {disk_serial}")
    print(f"CPU 序列号: {cpu_serial}")
    print(f"设备 UUID: {device_uuid}")
    print(f"设备特征码: {compressed_sequence}")
    # 等待用户按回车键继续
    input("\n按回车键退出...")
