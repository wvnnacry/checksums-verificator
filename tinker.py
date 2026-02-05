import json
import xml.etree.ElementTree as ET
import hashlib
import os
import sys
import zlib
from pathlib import Path



def calculate_crc32(filepath):
    with open(filepath, 'rb') as f:
        return zlib.crc32(f.read()) & 0xFFFFFFFF





def calculate_md5(filepath):
    try:
        return hashlib.md5(open(filepath, "rb").read()).hexdigest()
    except:
        return None



def calculate_sha256(filepath):
    try:
        with open(filepath, "rb") as file:
            data = file.read()
        return hashlib.sha256(data).hexdigest()
    except:
        return None


def parse_json_manifest(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    files_to_check = []


    if isinstance(data, dict):
        if 'files' in data:
            for file_info in data['files']:
                files_to_check.append({
                    'filename': file_info['filename'],
                    'expected': file_info.get('checksum') or file_info.get('crc32') or file_info.get('hash'),
                    'type': file_info.get('type', 'crc32').lower()
                })
        else:
            for filename, checksum in data.items():
                if isinstance(checksum, dict):
                    files_to_check.append({
                        'filename': filename,
                        'expected': checksum.get('checksum') or checksum.get('crc32') or checksum.get('hash'),
                        'type': checksum.get('type', 'crc32').lower()
                    })
                else:
                    files_to_check.append({
                        'filename': filename,
                        'expected': str(checksum),
                        'type': 'crc32'
                    })
    elif isinstance(data, list):
        for file_info in data:
            files_to_check.append({
                'filename': file_info['filename'],
                'expected': file_info.get('checksum') or file_info.get('crc32') or file_info.get('hash'),
                'type': file_info.get('type', 'crc32').lower()
            })

    return files_to_check


def parse_xml_manifest(filepath):
    tree = ET.parse(filepath)
    root = tree.getroot()

    files_to_check = []


    for elem in root.findall('.//file') or root.findall('.//checksum'):
        filename = elem.get('name') or elem.get('filename') or elem.get('path')
        if not filename:
            continue

        checksum = elem.get('checksum') or elem.get('crc32') or elem.get('hash') or elem.text
        checksum_type = elem.get('type', 'crc32').lower()

        files_to_check.append({
            'filename': filename,
            'expected': checksum,
            'type': checksum_type
        })

    return files_to_check


def normalize_checksum(checksum, checksum_type):
    if not checksum:
        return ""

    checksum = str(checksum).strip().lower()

    if checksum.startswith('0x'):
        checksum = checksum[2:]


    checksum = checksum.replace(' ', '')

    return checksum


def check_checksums(manifest_path):


    print(f"🔍 Проверяем файл манифеста: {manifest_path}")
    print("-" * 60)

    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        print(f"файл манифеста не найден: {manifest_path}")
        return False


    if manifest_path.suffix.lower() == '.json':
        try:
            files_to_check = parse_json_manifest(manifest_path)
        except json.JSONDecodeError as e:
            print(f"ошибка парсинга JSON: {e}")
            return False
    elif manifest_path.suffix.lower() == '.xml':
        try:
            files_to_check = parse_xml_manifest(manifest_path)
        except ET.ParseError as e:
            print(f"ошибка парсинга XML: {e}")
            return False
    else:
        print(f"неподдерживаемый формат файла: {manifest_path.suffix}")
        print("поддерживаются только .json и .xml файлы")
        return False

    if not files_to_check:
        print("в манифесте не найдены файлы для проверки")
        return True

    print(f"найдено {len(files_to_check)} файл(ов) для проверки")
    print("-" * 60)

    all_ok = True
    failed_files = []

    for i, file_info in enumerate(files_to_check, 1):
        filename = file_info['filename']
        expected = file_info['expected']
        checksum_type = file_info['type']

        print(f"{i}. Файл: {filename}")
        print(f"ожидаемая контрольная сумма ({checksum_type}): {expected}")


        if not os.path.exists(filename):
            print(f"файл не найден!")
            all_ok = False
            failed_files.append(f"{filename} (файл не найден)")
            print()
            continue


        if checksum_type == 'crc32':
            actual = calculate_crc32(filename)
            if actual is not None:
                actual_hex = f"{actual:08x}"
        elif checksum_type == 'md5':
            actual = calculate_md5(filename)
            actual_hex = actual
        elif checksum_type == 'sha256':
            actual = calculate_sha256(filename)
            actual_hex = actual
        else:
            print(f"неподдерживаемый тип контрольной суммы: {checksum_type}")
            print(f"пропускаем проверку этого файла")
            print()
            continue

        if actual is None:
            print(f"не удалось найтии контрольную сумму")
            all_ok = False
            failed_files.append(f"{filename} (ошибка вычисления)")
            print()
            continue


        expected_normalized = normalize_checksum(expected, checksum_type)
        actual_normalized = normalize_checksum(actual_hex, checksum_type)

        # Сравниваем
        if expected_normalized == actual_normalized:
            print(f"совпало")
        else:
            print(f"не совпало")
            print(f"должно быть: {actual_hex}")
            all_ok = False
            failed_files.append(filename)

        print()


    print("=" * 60)
    if all_ok:
        print("все контрольные суммы совпадают!")
        return True
    else:
        print("обнаружены несовпадения контрольных сумм:")
        for failed in failed_files:
            print(f"   - {failed}")
        return False


def main():
    if len(sys.argv) != 2:
        print("утилита для проверки контрольных сумм файлов")
        print("=" * 50)
        print("Использование:")
        print(f"  python {sys.argv[0]} <путь_к_файлу_манифеста>")
        print()
        print("примеры:")
        print(f"  python {sys.argv[0]} checksums.json")
        print(f"  python {sys.argv[0]} checksums.xml")
        print()
        print("файл манифеста должен быть только в формате JSON или XML")
        print("и содержать список файлов и их контрольные суммы")
        return 1

    manifest_path = sys.argv[1]
    success = check_checksums(manifest_path)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
