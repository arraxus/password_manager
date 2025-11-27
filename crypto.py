# Importowanie niezbędnych bibliotek
import os
import hashlib # do haszowania haseł
from cryptography.fernet import Fernet, InvalidToken # do szyfrowania i deszyfrowania haseł
import tkinter as tk # do tworzenia GUI
from tkinter import messagebox # do wyświetlania komunikatów
import hmac # do porównywania haszów
import random # do generowania losowych haseł
import string # do generowania znaków w hasłach

# Funkcja do wyświetlania okna z komunikatem o błędzie
def show_error(message):
    root = tk.Tk() # Tworzenie głównego okna
    root.withdraw() # Ukrywanie głównego okna
    messagebox.showerror("Błąd", message) # Wyświetlanie komunikatu o błędzie
    root.destroy() # Niszczenie głównego okna po zamknięciu komunikatu

# Funkcja do wyświetlania okna z komunikatem o powodzeniu operacji
def show_success(title, message):
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(title, message)
    root.destroy()

# Funkcja do generowania silnego losowego hasła
def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation # Zbiór znaków do użycia w haśle
    password = ''.join(random.choice(characters) for _ in range(length)) # Generowanie hasła
    return password

# Klasa obsługująca generowanie i wczytywanie klucza szyfrowania
class KeyManager:
    # Generacja nowego klucza szyfrowania i zapis go do pliku 'key.key'
    @staticmethod
    def generate_key():
        try:
            key = Fernet.generate_key()  # Generowanie nowego klucza szyfrowania
            with open("key.key", "wb") as key_file:
                key_file.write(key)
            return key
        except Exception as e:
            show_error(f"Błąd podczas generowania klucza: {e}")
            return None

    # Wczytania klucza szyfrowania z pliku 'key.key', jeśli istnieje
    @staticmethod
    def load_key():
        try:
            with open("key.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            show_error("Błąd: Plik z kluczem nie został znaleziony.")
            return None
        except Exception as e:
            show_error(f"Błąd podczas ładowania klucza: {e}")
            return None

# Funkcja do szyfrowania przy użyciu podanego klucza
def encrypt_password(key, password):
    try:
        fernet = Fernet(key) # Inicjalizacja obiektu Fernet z kluczem
        return fernet.encrypt(password.encode()).decode() # Szyfrowanie hasła i zwrócenie go jako string
    except Exception as e:
        show_error(f"Błąd podczas szyfrowania: {e}")
        return None

# Funkcja do deszyfrowania hasła przy użyciu podanego klucza
def decrypt_password(key, encrypted_password):
    try:
        # Deszyfrowanie hasła i zwrócenie go jako string
        return Fernet(key).decrypt(encrypted_password.encode()).decode()
    except InvalidToken:
        show_error("Błąd: Nieprawidłowy klucz.")
        return None
    except Exception as e:
        show_error(f"Błąd podczas deszyfrowania: {e}")
        return None

# Klasa do tworzenia i weryfikacji hasła głównego
class MasterPassword:
    # Metoda do haszowania hasła z wykorzystaniem PBKDF2 i SHA-256
    @staticmethod
    def hash_password(password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    # Metoda do tworzenia hasła głównego i zapisywania go w pliku
    @staticmethod
    def create_master_password(password):
        try:
            salt = os.urandom(16) # Generowanie losowej soli
            hashed_password = MasterPassword.hash_password(password, salt) # Haszowanie hasła z użyciem soli
            with open("master.hash", "wb") as f:
                f.write(salt + hashed_password)
            return True
        except Exception as e:
            show_error(f"Błąd podczas tworzenia hasła głównego: {e}")
            return False

    # Metoda do weryfikacji hasła głównego użytkownika
    @staticmethod
    def verify_master_password(password):
        try:
            with open("master.hash", "rb") as f:
                data = f.read()
                salt = data[:16] # Pierwsze 16 bajtów to sól
                stored_hash = data[16:] # Reszta to haszowane hasło
            # Haszowanie podanego hasła z użyciem tej samej soli
            hashed_password = MasterPassword.hash_password(password, salt)
            return hmac.compare_digest(hashed_password, stored_hash) # Porównanie haszów
        except FileNotFoundError:
            show_error("Błąd: Plik z hasłem głównym nie został znaleziony.")
            return False
        except Exception as e:
            show_error(f"Błąd podczas weryfikacji hasła głównego: {e}")
            return False
