# SafeGate USB 🛡️🔌

**Izolowana Stacja Sanityzacji Nośników Danych**

SafeGate USB to projekt typu Proof of Concept (PoC) mający na celu stworzenie bezpiecznej "śluzy" dla nieznanych nośników USB. System automatycznie wykrywa podłączone urządzenie, izoluje je od systemu operacyjnego hosta i przekazuje do odizolowanej maszyny wirtualnej w celu przeprowadzenia dogłębnej analizy bezpieczeństwa.

---

## 🚀 Kluczowe Funkcje

* **Automatyczna Detekcja:** Monitorowanie jądra systemu (udev) w celu natychmiastowego wykrycia nowych urządzeń USB.
* **Izolacja Hardware-Level:** Blokada automatycznego montowania (automount) na systemie hosta, zapobiegająca atakom typu autorun/BadUSB.
* **USB Passthrough:** Automatyczne przekazywanie urządzenia do bezpiecznego środowiska Guest VM (Oracle VirtualBox).
* **Analiza Cloud-Based:** Automatyczne generowanie sum kontrolnych SHA-256 i weryfikacja plików za pomocą API VirusTotal.
* **Raportowanie:** Przejrzysty werdykt o poziomie zagrożenia prezentowany użytkownikowi przed dopuszczeniem nośnika do pracy.

## 🏗️ Architektura Systemu

Projekt składa się z trzech głównych modułów:
1.  **Host Monitor:** Skrypt Python działający jako usługa, nasłuchujący zdarzeń systemowych.
2.  **VM Controller:** Moduł zarządzający stanem maszyny wirtualnej i tunelowaniem portów.
3.  **Analysis Engine:** Skrypt wewnątrz VM wykonujący skanowanie i komunikację z zewnętrznymi bazami zagrożeń.

## 🛠️ Technologie

* **Język:** Python 3.x
* **Biblioteki:** `pyudev`, `requests`, `hashlib`
* **Środowisko:** Linux (Ubuntu/Debian), Oracle VirtualBox
* **API:** VirusTotal Public API

## 📋 Wymagania Systemowe

* System operacyjny Linux z dostępem do uprawnień `sudo`.
* Zainstalowany VirtualBox wraz z Extension Pack (wymagany do obsługi kontrolerów USB 2.0/3.0).
* Aktywny klucz API VirusTotal (Public Plan).
* Procesor wspierający wirtualizację sprzętową (VT-x lub AMD-V).

## ⚠️ Bezpieczeństwo i Ryzyka

Projekt ma charakter edukacyjny i prototypowy. Główne założenia opierają się na izolacji maszyn wirtualnych. Należy pamiętać o ograniczeniach darmowych planów API (limit zapytań na minutę) oraz specyfice kontrolerów USB, które mogą wpływać na stabilność procesu passthrough.

## 👥 Autorzy i Role Projektowe

Projekt został zrealizowany przez zespół w składzie:

* Antoni Gąsiorowski – Project Manager (Zarządzanie harmonogramem, dokumentacja, testy integracyjne).
* Szymon Stolarski – Security Administrator (Hardening hosta, konfiguracja izolacji VM, USB passthrough).
* Kamil Wierzbicki– DevOps Engineer (Automatyzacja detekcji `udev`, skrypty sterujące VirtualBox CLI).
* Mateusz Majcher – Backend Developer (Logika analizy plików, integracja z API VirusTotal, system raportowania).

---
*Projekt realizowany w ramach zajęć akademickich. Budżet: 0 zł (Open Source).*
