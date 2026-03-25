import pyudev
import os
import subprocess
import hashlib


def hash(file, base_path):
    try:
        sha256_hash = hashlib.sha256()
        path = os.path.join(base_path, file)

        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        print("Podany plik nie istnieje")

    except Exception as e:
        print(f"Wystąpił inny błąd: {e}")


def directory_check(path):
    if os.path.isdir(path):
        print("Podany plik jest katalogiem")
        return True
    else:
        print("Jest to plik")
        return False


def list_files_recursive(path='.'):
    for entry in os.listdir(path):
        full_path = os.path.join(path, entry)
        if os.path.isdir(full_path):
            list_files_recursive(full_path)
        else:
            print(f"Plik: {full_path}")
            wynikowy_hash = hash(entry, path)
            if wynikowy_hash:
                print(f"Hash pliku {entry} wynosi: {wynikowy_hash}")
            print("###################################")


def main():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by('block')
    monitor.start()

    os.makedirs("/mnt/Pendrive", exist_ok=True)

    for dev in iter(monitor.poll, None):

        if dev.get('ID_FS_TYPE') and dev.get('ID_BUS') == 'usb':

            if dev.action == 'add':

                try:
                    sectors = int(dev.attributes.get('size'))
                    size_gb = (sectors * 512) / (1024**3)

                    print("###################################")
                    print("Wykryto podłączenie nośnika USB!!")
                    print("###################################")
                    print("Informacje o urządzeniu:")
                    print(f"Producent: {dev.get('ID_VENDOR_FROM_DATABASE')}")
                    print(f"Pojemność: {round(size_gb, 2)} Gb")
                    print("###################################")

                except (TypeError, ValueError) as e:
                    print(f"Błąd podczas odczytu danych: {e}")
                    continue

                try:
                    print("Próba zamontowania w trybie read-only")

                    subprocess.run(
                        ["sudo", "mount", "-o", "ro",
                         dev.device_node, "/mnt/Pendrive"],
                        check=True
                    )

                    mont = subprocess.run(
                        ["findmnt", "-n", "-o", "TARGET", dev.device_node],
                        capture_output=True,
                        text=True
                    )

                    if mont.returncode == 0:
                        punkt_mnt = mont.stdout.strip()

                        print(
                            f"Udało się zamontować dysk: {
                                dev.device_node} w: {punkt_mnt}")
                        print("###################################")

                        foldery = os.listdir(punkt_mnt)

                        print("Pendrive zawiera następujące pliki:")
                        list_files_recursive(punkt_mnt)

                    else:
                        print(
                            f"Dysk: {
                                dev.device_node} nie został zamontowany :(")

                except Exception as e:
                    print("Error podczas montowania:", e)

            elif dev.action == 'remove':

                print("###################################")
                print("Wykryto odłączenie nośnika USB!!")
                print("###################################")

                try:
                    subprocess.run(
                        ["sudo", "umount", "/mnt/Pendrive"], check=True)
                except Exception as e:
                    print("Błąd podczas odmontowania:", e)


if __name__ == "__main__":
    main()
