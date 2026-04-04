SafeGate USB 🛡️
Izolowana Stacja Sanityzacji Nośników Danych (PoC)

SafeGate USB to projekt typu Proof of Concept (PoC) służący do budowy bezpiecznej „śluzy” dla nieznanych nośników USB. System automatycznie wykrywa podłączone urządzenia, izoluje je od systemu operacyjnego hosta i przekazuje do dedykowanego, odizolowanego środowiska wirtualnego w celu przeprowadzenia dogłębnej analizy bezpieczeństwa.
🚀 Kluczowe Funkcje

    Automatyczna Detekcja: Wykorzystanie monitorowania jądra systemu (udev) do natychmiastowego wykrywania nowych zdarzeń na magistrali USB.

    Izolacja Hardware-Level: Całkowita blokada automatycznego montowania (automount) na systemie hosta, co eliminuje ryzyko ataków typu autorun oraz BadUSB.

    Dynamiczny USB Passthrough: Automatyczne przechwytywanie i przekazywanie urządzenia do bezpiecznego środowiska Guest VM (Oracle VirtualBox).

    Analiza Cloud-Based: Automatyczne generowanie sum kontrolnych SHA-256 dla plików i ich weryfikacja w oparciu o silniki VirusTotal (via API).

    System Raportowania: Generowanie przejrzystego werdyktu o poziomie zagrożenia przed dopuszczeniem nośnika do użytku w sieci wewnętrznej.

🏗️ Architektura Systemu

System opiera się na trzech ściśle współpracujących modułach:

    Host Monitor: Usługa Python działająca w tle, nasłuchująca zdarzeń systemowych udev.

    VM Controller: Moduł zarządzający cyklem życia maszyny wirtualnej i automatyzacją tunelowania portów USB.

    Analysis Engine: Skrypt działający wewnątrz odizolowanej maszyny VM, odpowiedzialny za skanowanie zawartości i komunikację z bazami zagrożeń.

🛠️ Stack Technologiczny

    Język: Python 3.x

    Biblioteki: pyudev, requests, hashlib

    Środowisko: Linux (Ubuntu/Debian), Oracle VirtualBox

    API: VirusTotal API v3

📋 Wymagania Systemowe

    System Linux z uprawnieniami sudo.

    VirtualBox + Extension Pack (niezbędny do obsługi kontrolerów USB 2.0/3.0).

    Klucz API VirusTotal (Public Plan).

    Procesor z aktywną wirtualizacją sprzętową (VT-x lub AMD-V).

⚠️ Bezpieczeństwo i Ryzyka

Projekt ma charakter edukacyjno-prototypowy. Główną warstwą ochronną jest izolacja na poziomie hypervisora. Należy uwzględnić limity darmowego planu API VirusTotal oraz specyfikę kontrolerów USB, która w rzadkich przypadkach może wpływać na stabilność procesu passthrough.
👥 Zespół projektowy

Projekt został zrealizowany przez:

    Antoni Gąsiorowski

    Szymon Stolarski

    Kamil Wierzbicki

    Mateusz Majcher
