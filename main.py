# Importowanie niezbędnych bibliotek i modułów
import os # do sprawdzania istnienia plików
import json # do obsługi plików JSON
# funkcje szyfrowania i deszyfrowania haseł
from crypto import encrypt_password, decrypt_password, show_error, show_success

# Klasa reprezentuje podstawowy wpis hasła zawierający usługę, nazwę użytkownika i hasło
class EnterPassword:
    # Inicjalizacja nowego obiekt EnterPassword.
    def __init__(self, service, username, password):
        self.service = service # Nazwa usługi, do której należy hasło
        self.username = username # Nazwa użytkownika powiązana z usługą
        self.password = password # Hasło w postaci jawnej

    # Zwrócenie tekstowej reprezentacji obiektu
    def __str__(self):
        return f"{self.service} ({self.username})"

# Rozszerzenie klasy EnterPassword o możliwość przechowywania zaszyfrowanego hasła
class SafeEnterPassword(EnterPassword):
    # Utworzenie nowego obiektu SafeEnterPassword
    def __init__(self, service, username, password):
        super().__init__(service, username, password)
        self.encrypted_password = None

    # Porównanie dwóch obiektów EnterPassword
    def __eq__(self, other):
        if not isinstance(other, EnterPassword):
            return False
        return (self.service == other.service and
                self.username == other.username and
                self.password == other.password)

# Klasa zarządzająca listą zaszyfrowanych haseł
class PasswordManager:
    # Inicjalizacja menedżera haseł z kluczem szyfrowania
    def __init__(self, key):
        self.key = key
        self.passwords = []

    # Wyszukanie hasła na podstawie nazwy usługi i użytkownika
    def find_password(self, service, username):
        service = str(service).strip().lower() # Normalizacja nazwy usługi
        username = str(username)
        for password in self.passwords: # Iteracja przez wszystkie hasła
            if password.service.lower() == service and password.username == username:
                return password
        return None

    # Deszyfrowanie hasła na podstawie zaszyfrowanej wersji
    def decrypt_password(self, encrypted_password):
        try:
            return decrypt_password(self.key, encrypted_password)
        except Exception as e:
            raise ValueError(f"Błąd podczas deszyfrowania hasła: {e}")

    # Zapisanie listy zaszyfrowanych haseł do pliku JSON
    def save_passwords(self, filename="passwords.json"):
        json_data = []
        for password in self.passwords: # Iteracja przez wszystkie hasła
            json_data.append({
                "service": password.service,
                "username": password.username,
                "password": password.encrypted_password
            })
        encrypted_data = encrypt_password(self.key, json.dumps(json_data)) # Szyfrowanie danych JSON
        try:
            with open(filename, "wb") as f:
                f.write(encrypted_data.encode())
        except Exception as e:
            show_error(f"Błąd podczas zapisu pliku: {e}")

    # Dodanie nowego hasła do menedżera i zapisanie go na dysku
    def add_password(self, password):
        password.encrypted_password = encrypt_password(self.key, password.password) # Szyfrowanie hasła
        password.password = None
        self.passwords.append(password) # Dodanie hasła do listy
        self.save_passwords() # Zapisanie listy haseł do pliku

    # Usunięcie hasła z listy na podstawie usługi i użytkownika
    def remove_password(self, password):
        self.passwords = [p for p in self.passwords if not (p.service == password.service and
                                                            p.username == password.username)]
        self.save_passwords()

    # Wczytanie haseł z pliku i odszyfrowanie ich
    def load_passwords(self, filename="passwords.json"):
        if not os.path.exists(filename):
            return None
        try:
            # Odczytanie zaszyfrowanych danych z pliku
            with open(filename, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = decrypt_password(self.key, encrypted_data.decode())
            json_data = json.loads(decrypted_data)
            existing = {(p.service.lower(), p.username.lower()) for p in self.passwords}
            added_any = False

            # Iteracja przez odszyfrowane dane i dodanie nowych haseł
            for item in json_data:
                key = (item["service"].lower(), item["username"].lower())
                if key not in existing:
                    password = SafeEnterPassword(item["service"], item["username"], None)
                    password.encrypted_password = item["password"]
                    password.password = decrypt_password(self.key, password.encrypted_password)
                    self.passwords.append(password)
                    existing.add(key)
                    added_any = True
            return added_any

        except json.JSONDecodeError:
            show_error("Błąd podczas deszyfrowania pliku. Upewnij się, że plik jest poprawny.")
            return False
        except Exception as e:
            show_error(f"Błąd podczas ładowania pliku: {e}")
            return False

    # Eksportowanie wszystkich haseł do zewnętrznego pliku
    def export_passwords(self, filename):
        try:
            self.save_passwords(filename)
            show_success("Sukces", "Hasła zostały wyeksportowane.")
            return None
        except FileNotFoundError:
            show_error("Błąd: Plik nie został znaleziony.")
            return False
        except PermissionError:
            show_error("Błąd: Brak uprawnień do zapisu w pliku.")
            return False
        except Exception as e:
            show_error(f"Błąd podczas eksportowania haseł: {e}")
            return False

    # Importowanie haseł z pliku i dodanie ich do menedżera
    def import_passwords(self, filename):
        imported = self.load_passwords(filename) # Wczytanie haseł z pliku
        if imported:
            try:
                self.save_passwords()
                show_success("Sukces", "Nowe hasła zostały zaimportowane.")
            except Exception as e:
                show_error(f"Błąd podczas importowania haseł: {e}")
        else:
            show_success("Uwaga", "Brak nowych haseł, plik pusty lub nieprawidłowy.")
