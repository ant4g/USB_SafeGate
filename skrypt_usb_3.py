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
                        for n in foldery:
                            print(n)

                        print("###################################")
                        print("Obliczanie hashy:")
                        print("###################################")

                        for k in foldery:
                            full_path = os.path.join(punkt_mnt, k)

                            if directory_check(full_path):
                                print(f"{k} to katalog")
                                print("###################################")
                                foldery2 = os.listdir(full_path)
                                try:
                                    for p in foldery2:
                                        print(
                                            "###################################")
                                        print("Obliczanie hashy:")
                                        print("Listowanie katalogów: ")
                                        print(p)
                                except FileNotFoundError:
                                    print("Nie ma takiego pliku")
                                except PermissionError:
                                    print("Brak uprawnień")

                            wynikowy_hash = hash(k, punkt_mnt)
                            print(f"Hash pliku: {k}  wynosi: {wynikowy_hash}")
                            print("###################################")

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
