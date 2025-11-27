# Password Manager
> [!CAUTION]
> Projektu nie należy traktować jako użyteczny i bezpieczny manadżer haseł.

Lekki menedżer haseł napisany w Pythonie z GUI opartym o `tkinter`. Aplikacja szyfruje hasła kluczem symetrycznym, wymaga hasła głównego i przechowuje dane lokalnie w plikach: `passwords.json`, `master.hash`, `key.key`.

## Najważniejsze funkcje
- Rejestracja i weryfikacja hasła głównego.
- Tworzenie, edycja, usuwanie, eksport/import haseł (JSON).
- Generowanie silnych haseł.
- Wyświetlanie i kopiowanie odszyfrowanych haseł po ponownej weryfikacji.
- Reset aplikacji (usuwa wszystkie pliki konfiguracyjne i dane).

## Wymagania
- System: Windows (środowisko testowe)
- Python 3.10+
- Biblioteki: `tkinter`, `cryptography`

## Instalacja (Windows)
1. Utwórz i aktywuj wirtualne środowisko:
   - `python -m venv .venv`
   - `.venv\Scripts\activate`
2. Zainstaluj zależności:
   - `pip install -r requirements.txt`
3. Uruchom aplikację:
   - `python gui.py`
   - W PyCharm: otwórz projekt i uruchom `gui.py`.

## Użycie
- Pierwsze uruchomienie: zostaniesz poproszony o stworzenie hasła głównego. Silne hasło jest wymagane.
- Kolejne uruchomienia: logowanie przy użyciu hasła głównego (maks. 3 próby).
- Po zalogowaniu GUI umożliwia dodawanie/edycję/usuwanie i eksport/import haseł.
- Reset aplikacji usuwa `passwords.json`, `master.hash` i `key.key` i uruchamia program ponownie.

## Pliki i struktura
- `gui.py` - interfejs graficzny i logika użytkownika.
- `main.py` - logika menedżera haseł (ładowanie, zapisywanie, wyszukiwanie).
- `crypto.py` - zarządzanie kluczem szyfrującym, tworzenie i weryfikacja `master.hash`, generowanie haseł.
- `utility.py` - pomocnicze funkcje GUI (centrowanie okien, tworzenie pól hasła, walidacje).
- Dane tworzone w czasie działania: `passwords.json`, `master.hash`, `key.key`.

## Bezpieczeństwo
- Nie udostępniać `key.key` ani `master.hash`.
- Hasło główne musi być silne - aplikacja wymusza to przy rejestracji.
- Przechowywanie danych odbywa się lokalnie - projekt nie wysyła danych na zewnątrz.
