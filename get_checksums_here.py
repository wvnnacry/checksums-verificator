import hashlib
import sys
import zlib


def get_crc32(filename):
    try:
        with open(filename, 'rb') as f:
            return zlib.crc32(f.read()) & 0xFFFFFFFF
    except:
        return None


def get_hash(filename, algorithm='md5'):
    hash_func = hashlib.new(algorithm)
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python get_checksums_here.py <файл1> [файл2 ...]")
        sys.exit(1)

    for filename in sys.argv[1:]:
        crc32 = get_crc32(filename)
        md5 = get_hash(filename, 'md5')
        sha256 = get_hash(filename, 'sha256')

        print(f"\nфайл: {filename}")
        print(f"  CRC32:    {crc32:08x}  (или 0x{crc32:08x})")
        print(f"  MD5:      {md5}")
        print(f"  SHA256:   {sha256}")