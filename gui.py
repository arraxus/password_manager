# Importowanie niezbędnych bibliotek i modułów
import os # do sprawdzania istnienia plików
import sys # do obsługi argumentów wiersza poleceń
import tkinter as tk # do tworzenia GUI
from tkinter import ttk, messagebox, filedialog # do obsługi komunikatów i dialogów
from ctypes import windll # do wymuszenia obsługi DPI w Windows
from main import PasswordManager, SafeEnterPassword # do zarządzania hasłami
from crypto import KeyManager, MasterPassword, generate_strong_password # do szyfrowania i deszyfrowania haseł
from typing import Optional # do obsługi typów opcjonalnych
# do obsługi interfejsu użytkownika i weryfikacji hasła głównego
from utility import (center_window, limited_entry, create_password_field,
                     verify_master_password_dialog, calculate_password_strength)

# Wymuszenie obsługi DPI w Windows, aby uniknąć problemów z wyświetlaniem GUI
try:
    windll.shcore.SetProcessDpiAwareness(1) # Ustawienie DPI na "System DPI Aware"
except Exception as e:
    pass

# Główna klasa aplikacji GUI
class App:
    def __init__(self, gui_root):
        # Inicjalizacja głównego okna aplikacji
        self.root = gui_root
        self.tree: Optional[ttk.Treeview] = None # Drzewo do wyświetlania haseł
        self.root.title("Menedżer Haseł")
        self.root.geometry("580x380")
        center_window(self.root)

        # Wczytanie lub utworzenie klucza szyfrującego
        self.key = self.load_key()
        self.password_manager = PasswordManager(self.key)
        self.password_manager.load_passwords()

        self.authenticated = False
        self.login_attempts = 0

    # Metoda do wczytania klucza szyfrującego lub generacji, jeśli nie istnieje
    @staticmethod
    def load_key():
        if not os.path.exists("key.key"):
            KeyManager.generate_key()
        return KeyManager.load_key()

    # Metoda do autoryzacji użytkownika poprzez weryfikację hasła głównego
    def authenticate(self):
        # Sprawdza, czy użytkownik jest zarejestrowany – jeśli nie, wymusza rejestrację
        if not os.path.exists("master.hash"):
            # Okno do tworzenia hasła głównego
            register_window = tk.Toplevel(self.root)
            register_window.title("Zarejestruj się")
            register_window.geometry("310x245")
            register_window.resizable(False, False)
            center_window(register_window)

            def on_close():
                messagebox.showinfo("Status", "Rejestracja została anulowana.")
                register_window.destroy()
                self.root.destroy()

            register_window.protocol("WM_DELETE_WINDOW", on_close) # Ustawienie funkcji zamykania okna

            # Funkcja do tworzenia pola hasła z ograniczeniem długości i filtrowaniem znaków
            tk.Label(register_window, text="Utwórz hasło główne:").pack(pady=5)
            password_entry1, password_var1 = create_password_field(register_window, "*", True)
            password_entry1.focus_set()

            # Funkcja do tworzenia drugiego pola hasła do potwierdzenia
            tk.Label(register_window, text="Potwierdź hasło główne:").pack(pady=5)
            password_entry2, password_var2 = create_password_field(register_window)

            # Funkcja do zapisywania hasła głównego po weryfikacji
            def save_master_password():
                password1 = password_var1.get()
                password2 = password_var2.get()
                if not password1 or not password2: # Sprawdzenie, czy hasła nie są puste
                    messagebox.showerror("Błąd", "Hasła nie mogą być puste.")
                    password_entry1.focus_set()
                    return
                if password1 != password2: # Sprawdzenie, czy hasła są zgodne
                    messagebox.showerror("Błąd", "Hasła nie są zgodne.")
                    password_entry2.focus_set()
                    return
                strength, _ = calculate_password_strength(password1)
                if strength != "Silne": # Sprawdzenie siły hasła
                    messagebox.showerror("Błąd", "Hasło musi być silne.")
                    password_entry1.focus_set()
                    return
                MasterPassword.create_master_password(password1)
                messagebox.showinfo("Sukces", "Hasło zostało utworzone.")
                self.authenticated = True
                register_window.destroy()

            def cancel_registration():
                on_close()

            # Tworzenie przycisków do zapisu i anulowania rejestracji
            button_frame = tk.Frame(register_window)
            button_frame.pack(pady=5)
            tk.Button(button_frame, text="Zapisz", command=save_master_password).pack(side="left", padx=5)
            tk.Button(button_frame, text="Anuluj", command=cancel_registration).pack(side="right", padx=5)

            # Obsługa klawiszy Enter i Escape
            register_window.bind("<Return>", lambda _: save_master_password())
            register_window.bind("<Escape>", lambda _: cancel_registration())
            self.root.wait_window(register_window)
        else:
            # Okno do logowania, jeśli hasło główne już istnieje
            login_window = tk.Toplevel(self.root)
            login_window.title("Logowanie")
            login_window.geometry("290x165")
            login_window.resizable(False, False)
            center_window(login_window)

            # Tworzenie etykiety i pola do wprowadzenia hasła
            tk.Label(login_window, text="Wprowadź hasło:").pack(pady=5)
            password_entry, password_var = create_password_field(login_window)
            password_entry.focus_set()

            # Etykieta do wyświetlania pozostałych prób logowania
            attempts_label = tk.Label(login_window, text=f"Pozostałe próby: {3 - self.login_attempts}")
            attempts_label.pack(pady=2)

            # Funkcja do weryfikacji hasła głównego
            def verify_password():
                master_password = password_var.get()
                if MasterPassword.verify_master_password(master_password):
                    messagebox.showinfo("Sukces", "Hasło poprawne.")
                    self.authenticated = True
                    login_window.destroy()
                else:
                    self.login_attempts += 1
                    if self.login_attempts >= 3: # Przekroczenie maksymalnej liczby prób logowania
                        messagebox.showerror("Błąd", "Przekroczono maksymalną liczbę prób logowania.")
                        self.root.destroy()
                    else: # Aktualizacja etykiety z liczbą pozostałych prób
                        attempts_label.config(text=f"Pozostałe próby: {3 - self.login_attempts}")
                        messagebox.showerror("Błąd", "Niepoprawne hasło.")
                        password_entry.focus_set()

            # Funkcja do anulowania logowania i zamknięcia aplikacji
            def cancel_login():
                login_window.destroy()
                self.root.destroy()

            # Tworzenie przycisków do logowania i anulowania
            button_frame = tk.Frame(login_window)
            button_frame.pack(pady=5)
            tk.Button(button_frame, text="Zaloguj się", command=verify_password).pack(side="left", padx=5)
            tk.Button(button_frame, text="Anuluj", command=cancel_login).pack(side="right", padx=5)

            # Obsługa klawiszy Enter i Escape
            password_entry.bind("<Return>", lambda _: verify_password())
            password_entry.bind("<Escape>", lambda _: cancel_login())

            self.root.wait_window(login_window) # Oczekiwanie na zamknięcie okna logowania

        return self.authenticated

    # Metoda do budowania interfejsu graficznego aplikacji
    def build_gui(self):
        self.root.wm_minsize(500, 300) # Ustawienie minimalnego rozmiaru okna

        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill="both", expand=True) # Ramka dla drzewa haseł

        # Tworzenie paska przewijania dla drzewa haseł
        scrollbar = tk.Scrollbar(tree_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        # Tworzenie drzewa do wyświetlania haseł
        self.tree = ttk.Treeview(tree_frame, columns=("Service", "Username"), show="headings")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.heading("Service", text="Serwis")
        self.tree.heading("Username", text="Login")
        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar.config(command=self.tree.yview) # Połączenie paska przewijania z drzewem

        # Dodanie przycisków do interfejsu
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(side="bottom", fill="x")

        # Tworzenie przycisków do zarządzania hasłami
        button_container = tk.Frame(btn_frame)
        button_container.pack(expand=True, anchor="center")
        tk.Button(button_container, text="Pokaż", command=self.show_passwords).pack(side="left")
        tk.Button(button_container, text="Dodaj", command=self.add_passwords).pack(side="left")
        tk.Button(button_container, text="Edytuj", command=self.edit_password).pack(side="left")
        tk.Button(button_container, text="Usuń", command=self.remove_passwords).pack(side="left")
        tk.Button(button_container, text="Eksportuj", command=self.export_passwords).pack(side="left")
        tk.Button(button_container, text="Importuj", command=self.import_passwords).pack(side="left")

        # Przycisk do resetowania aplikacji
        reset_button = tk.Button(self.root, text="Resetuj", command=self.reset_application, fg="white", bg="red")
        reset_button.place(relx=0, rely=1, anchor="sw")

        self.refresh_tree()

    # Metoda do wyświetlania hasła dla wybranego serwisu i użytkownika
    def show_passwords(self):
        selected_item = self.tree.selection() # Pobranie zaznaczonego elementu z drzewa

        if selected_item:
            # Pobranie danych z zaznaczonego elementu
            item = self.tree.item(selected_item[0])
            service = item['values'][0]
            username = item['values'][1]
            password = self.password_manager.find_password(service, username)

            # Sprawdzenie, czy hasło zostało znalezione
            if password:
                if verify_master_password_dialog():
                    # Deszyfrowanie hasła
                    decrypted_password = self.password_manager.decrypt_password(password.encrypted_password)

                    # Funkcja do kopiowania hasła do schowka
                    def copy_to_clipboard():
                        self.root.clipboard_clear()
                        self.root.clipboard_append(decrypted_password)
                        self.root.update()
                        messagebox.showinfo("Sukces", "Hasło zostało skopiowane do schowka.")

                    # Tworzenie okna dialogowego do wyświetlania hasła
                    dialog = tk.Toplevel(self.root)
                    dialog.title("Hasło")
                    dialog.geometry("330x165")
                    dialog.resizable(False, False)
                    center_window(dialog)
                    dialog.transient(self.root)
                    dialog.grab_set()
                    dialog.focus_set()

                    # Etykiety do wyświetlania informacji o serwisie, loginie i haśle
                    tk.Label(dialog, text=f"Serwis: {service}").pack(pady=5)
                    tk.Label(dialog, text=f"Login: {username}").pack(pady=5)
                    tk.Label(dialog, text=f"Hasło: {decrypted_password}").pack(pady=5)

                    # Ramka na przyciski do kopiowania hasła i zamykania okna
                    button_frame = tk.Frame(dialog)
                    button_frame.pack(pady=5)
                    tk.Button(button_frame, text="Kopiuj do schowka", command=copy_to_clipboard).pack(side="left", padx=5)
                    tk.Button(button_frame, text="Zamknij", command=dialog.destroy).pack(side="right", padx=5)

                    # Obsługa klawiszy Enter i Escape
                    dialog.bind("<Return>", lambda _: copy_to_clipboard())
                    dialog.bind("<Escape>", lambda _: dialog.destroy())

                    dialog.wait_window()
            else:
                messagebox.showerror("Błąd", "Nie znaleziono hasła dla wybranego serwisu.")
        else:
            messagebox.showerror("Błąd", "Nie wybrano żadnego serwisu.")

    # Metoda dodawania nowego hasła
    def add_passwords(self):
        # Funkcja do dodawania nowego hasła
        def save_password():
            service = service_var.get().strip().lower() # Normalizacja nazwy usługi
            username = username_var.get().strip() # Normalizacja nazwy użytkownika
            password = password_var.get() # Pobranie hasła z pola tekstowego
            if service and username and password: # Sprawdzenie, czy wszystkie pola są wypełnione
                if self.password_manager.find_password(service, username):
                    messagebox.showerror("Błąd", f"Ten login w serwisie {service} już istnieje.")
                    return
                new_password = SafeEnterPassword(service, username, password) # Utworzenie nowego obiektu SafeEnterPassword
                self.password_manager.add_password(new_password) # Dodanie hasła do menedżera
                self.refresh_tree() # Odświeżenie drzewa haseł
                add_window.destroy()
            else:
                messagebox.showerror("Błąd", "Wszystkie pola są wymagane.")

        # Funkcja do anulowania dodawania hasła
        def cancel():
            add_window.destroy()

        # Funkcja do generowania silnego hasła
        def generate_password():
            strong_password = generate_strong_password()
            password_var.set(strong_password)

        # Tworzenie okna do dodawania nowego hasła
        add_window = tk.Toplevel(self.root)
        add_window.title("Dodaj hasło")
        add_window.geometry("265x347")
        add_window.resizable(False, False)
        center_window(add_window)
        add_window.transient(self.root)
        add_window.grab_set()

        # Etykiety i pola do wprowadzania danych
        tk.Label(add_window, text="Serwis:").pack(pady=5)
        service_entry, service_var = limited_entry(add_window)
        service_entry.pack(pady=5)
        service_entry.focus_set()

        tk.Label(add_window, text="Login:").pack(pady=5)
        username_entry, username_var = limited_entry(add_window)
        username_entry.pack(pady=5)

        tk.Label(add_window, text="Hasło:").pack(pady=5)
        password_entry, password_var = create_password_field(add_window, "*", True)

        # Ramka na przyciski do generowania hasła, zapisywania i anulowania
        button_frame = tk.Frame(add_window)
        button_frame.pack(pady=1)
        tk.Button(button_frame, text="Generuj hasło", command=generate_password).pack(side="top", fill="x",
                                                                                      padx=5, pady=5)
        tk.Button(button_frame, text="Zapisz", command=save_password).pack(side="left", padx=5)
        tk.Button(button_frame, text="Anuluj", command=cancel).pack(side="right", padx=5)

        # Obsługa klawiszy Enter i Escape
        add_window.bind("<Return>", lambda _: save_password())
        add_window.bind("<Escape>", lambda _: cancel())

    # Metoda edycji istniejącego hasła
    def edit_password(self):
        # Pobranie zaznaczonego elementu z drzewa
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Błąd", "Nie wybrano żadnego wpisu do edycji.")
            return

        # Pobranie danych z zaznaczonego elementu
        item = self.tree.item(selected_item[0])
        service = item['values'][0]
        username = item['values'][1]
        password = self.password_manager.find_password(service, username)

        if not password:
            messagebox.showerror("Błąd", "Nie znaleziono wpisu.")
            return

        # Weryfikacja hasła głównego przed edycją
        if not verify_master_password_dialog():
            return

        # Funkcja do zapisywania edytowanego hasła
        def save_password():
            new_service = service_var.get().strip().lower()
            new_username = username_var.get().strip()
            new_password = password_var.get()
            if new_service and new_username and new_password:
                self.password_manager.remove_password(password)
                updated_password = SafeEnterPassword(new_service, new_username, new_password)
                self.password_manager.add_password(updated_password)
                self.refresh_tree()
                edit_window.destroy()
            else:
                messagebox.showerror("Błąd", "Wszystkie pola są wymagane.")

        # Funkcja do anulowania edycji hasła
        def cancel():
            edit_window.destroy()

        # Funkcja do generowania silnego hasła
        def generate_password():
            strong_password = generate_strong_password()
            password_var.set(strong_password)

        # Tworzenie okna do edycji hasła
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edytuj hasło")
        edit_window.geometry("265x347")
        edit_window.resizable(False, False)
        center_window(edit_window)
        edit_window.transient(self.root)
        edit_window.grab_set()

        # Etykiety i pola do wprowadzania danych
        tk.Label(edit_window, text="Serwis:").pack(pady=5)
        service_entry, service_var = limited_entry(edit_window)
        service_var.set(service)
        service_entry.pack(pady=5)
        service_entry.focus_set()

        tk.Label(edit_window, text="Login:").pack(pady=5)
        username_entry, username_var = limited_entry(edit_window)
        username_var.set(username)
        username_entry.pack(pady=5)

        tk.Label(edit_window, text="Hasło:").pack(pady=5)
        password_entry, password_var = create_password_field(edit_window, "*", True)
        password_var.set(self.password_manager.decrypt_password(password.encrypted_password))

        # Ramka na przyciski do generowania hasła, zapisywania i anulowania
        button_frame = tk.Frame(edit_window)
        button_frame.pack(pady=1)
        tk.Button(button_frame, text="Generuj hasło", command=generate_password).pack(side="top", fill="x",
                                                                                      padx=5, pady=5)
        tk.Button(button_frame, text="Zapisz", command=save_password).pack(side="left", padx=5)
        tk.Button(button_frame, text="Anuluj", command=cancel).pack(side="right", padx=5)

        # Obsługa klawiszy Enter i Escape
        edit_window.bind("<Return>", lambda _: save_password())
        edit_window.bind("<Escape>", lambda _: cancel())

    # Metoda do usuwania hasła
    def remove_passwords(self):
        # Pobranie zaznaczonego elementu z drzewa
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Błąd", "Nie wybrano żadnego hasła.")
            return

        # Pobranie danych z zaznaczonego elementu
        item = self.tree.item(selected_item[0])
        service = str(item['values'][0])
        username = item['values'][1]
        password = self.password_manager.find_password(service, username)

        # Sprawdzenie, czy hasło zostało znalezione
        if not password:
            messagebox.showerror("Błąd", "Nie znaleziono hasła.")
            return

        # Weryfikacja hasła głównego przed usunięciem
        if not verify_master_password_dialog():
            return

        # Potwierdzenie usunięcia hasła
        self.password_manager.remove_password(password)
        self.refresh_tree()
        messagebox.showinfo("Sukces", "Hasło zostało usunięte.")

    # Metody do eksportowania i importowania haseł
    def export_passwords(self):
        # Okno dialogowe do wyboru pliku do eksportu haseł
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            self.password_manager.export_passwords(filename)
            self.refresh_tree()

    def import_passwords(self):
        # Okno dialogowe do wyboru pliku do importu haseł
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            self.password_manager.import_passwords(filename)
            self.refresh_tree()

    # Metoda do odświeżania drzewa haseł
    def refresh_tree(self):
        # Usunięcie wszystkich elementów z drzewa i ponowne wstawienie posortowanych haseł
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Sortowanie haseł według nazwy usługi i wstawienie ich do drzewa
        sorted_passwords = sorted(self.password_manager.passwords, key=lambda p: p.service.lower())

        # Wstawianie posortowanych haseł do drzewa
        for password in sorted_passwords:
            self.tree.insert("", "end", values=(password.service, password.username))

    # Metoda do resetowania aplikacji
    def reset_application(self):
        # Funkcja do potwierdzenia resetu aplikacji
        def confirm_reset():
            # Okno do potwierdzenia resetu aplikacji
            confirm_window = tk.Toplevel(self.root)
            confirm_window.title("Potwierdzenie resetu")
            confirm_window.geometry("328x282")
            confirm_window.resizable(False, False)
            center_window(confirm_window)
            confirm_window.transient(self.root)
            confirm_window.grab_set()

            # Etykiety informacyjne w oknie potwierdzenia
            tk.Label(confirm_window, text="Czy na pewno chcesz zresetować aplikację?").pack(pady=10)
            tk.Label(confirm_window, text="Operacja jest nieodwracalna!").pack(pady=5)

            # Funkcja do weryfikacji hasła głównego przed resetem
            def verify_reset():
                password1 = password1_var.get() # Pobranie hasła z pierwszego pola
                password2 = password2_var.get() # Pobranie hasła z drugiego pola

                if not password1 or not password2: # Sprawdzenie, czy hasła nie są puste
                    messagebox.showerror("Błąd", "Hasła nie mogą być puste.")
                    return
                if password1 != password2: # Sprawdzenie, czy hasła są zgodne
                    messagebox.showerror("Błąd", "Hasła nie są zgodne.")
                    return

                # Weryfikacja hasła głównego
                if MasterPassword.verify_master_password(password1):
                    try:
                        for file in ["passwords.json", "master.hash", "key.key"]:
                            if os.path.exists(file):
                                os.remove(file)
                        messagebox.showinfo("Sukces", "Aplikacja została zresetowana.")
                        self.root.destroy() # Zamykanie głównego okna aplikacji
                        os.environ["TK_FORCE_TOP"] = "1" # Ustawienie zmiennej środowiskowej do wymuszenia uruchomienia nowej instancji
                        os.execl(sys.executable, sys.executable, *sys.argv) # Uruchomienie nowej instancji aplikacji
                    except Exception as e1:
                        messagebox.showerror("Błąd", f"Nie udało się zresetować aplikacji: {e1}")
                else:
                    messagebox.showerror("Błąd", "Niepoprawne hasło główne.")

            # Tworzenie pól do wprowadzenia hasła głównego
            password1_var = tk.StringVar()
            password2_var = tk.StringVar()

            # Etykiety i pola do wprowadzenia hasła głównego
            tk.Label(confirm_window, text="Wpisz hasło główne:").pack(pady=5)
            password1_entry = tk.Entry(confirm_window, textvariable=password1_var, show="*")
            password1_entry.pack(pady=5)
            password1_entry.focus_set()

            tk.Label(confirm_window, text="Potwierdź hasło główne:").pack(pady=5)
            password2_entry = tk.Entry(confirm_window, textvariable=password2_var, show="*")
            password2_entry.pack(pady=5)

            # Ramka na przyciski do resetu i anulowania
            button_frame = tk.Frame(confirm_window)
            button_frame.pack(pady=10)
            tk.Button(button_frame, text="Resetuj", command=verify_reset, fg="white", bg="red").pack(side="left",
                                                                                                     padx=5)
            tk.Button(button_frame, text="Anuluj", command=confirm_window.destroy).pack(side="right", padx=5)

            # Obsługa klawiszy Enter i Escape
            confirm_window.bind("<Return>", lambda _: verify_reset())
            confirm_window.bind("<Escape>", lambda _: confirm_window.destroy())

        confirm_reset()

# Punkt wejścia do aplikacji
if __name__ == "__main__":
    root = tk.Tk() # Utworzenie głównego okna aplikacji
    root.withdraw() # Ukrycie głównego okna podczas autoryzacji
    app = App(root) # Inicjalizacja aplikacji

    # Autoryzacja użytkownika przed uruchomieniem GUI
    if app.authenticate():
        root.deiconify() # Pokazanie głównego okna po autoryzacji
        try:
            app.key = app.load_key() # Wczytanie klucza szyfrowania
            app.build_gui() # Budowanie GUI aplikacji
            root.mainloop() # Uruchomienie głównej pętli aplikacji
        except FileNotFoundError as e:
            messagebox.showerror("Błąd", str(e))
            root.destroy()
