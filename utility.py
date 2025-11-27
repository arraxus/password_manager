# Importowanie niezbędnych bibliotek
import string # do obsługi znaków
import tkinter as tk # do tworzenia GUI
from tkinter import messagebox # do wyświetlania komunikatów
from crypto import MasterPassword # do obsługi hasła głównego

# Funkcja do ustawiania okna na środku ekranu
def center_window(window):
    window.update_idletasks() # Aktualizuje rozmiar okna przed centrowaniem
    width = window.winfo_width() # Pobiera szerokość okna
    height = window.winfo_height() # Pobiera wysokość okna
    screen_width = window.winfo_screenwidth() # Pobiera szerokość ekranu
    screen_height = window.winfo_screenheight() # Pobiera wysokość ekranu
    x = (screen_width // 2) - (width // 2) # Oblicza współrzędną X, aby okno było wyśrodkowane
    y = (screen_height // 2) - (height // 2) # Oblicza współrzędną Y, aby okno było wyśrodkowane
    window.geometry(f"{width}x{height}+{x}+{y}") # Ustawia nowe położenie okna

MAX_FIELD_LENGTH = 64 # Maksymalna długość pola tekstowego
# Funkcja do tworzenia pola tekstowego z ograniczeniem długości i filtrowaniem znaków
def limited_entry(master, max_len=MAX_FIELD_LENGTH, **kwargs):
    var = tk.StringVar() # Tworzy zmienną tekstową do przechowywania wartości pola

    # Usuwa znaki niedrukowalne i ogranicza długość
    def validate_input(*_):
        value = var.get() # Pobiera aktualną wartość zmiennej
        # Usuwa znaki niedrukowalne i białe znaki
        sanitized_value = ''.join(c for c in value.strip() if c.isprintable() and c not in {'\n', '\r', '\t'})
        if len(sanitized_value) > max_len:
            sanitized_value = sanitized_value[:max_len] # Ogranicza długość do maksymalnej wartości
        if sanitized_value != value:
            var.set(sanitized_value) # Ustawia zmienioną wartość z powrotem do zmiennej

    var.trace_add("write", validate_input) # Dodaje śledzenie zmian w zmiennej
    entry = tk.Entry(master, textvariable=var, **kwargs) # Tworzy pole tekstowe z przekazanymi argumentami
    return entry, var

# Tworzy okno dialogowe do weryfikacji hasła głównego.
def verify_master_password_dialog():
    # Funkcja do weryfikacji hasła głównego.
    def verify_password():
        master_password = password_var.get() # Pobiera hasło z pola tekstowego
        if not master_password:
            messagebox.showerror("Błąd", "Niepoprawne hasło główne.")
            dialog.destroy()
            return
        if MasterPassword.verify_master_password(master_password):
            nonlocal result # Ustawia zmienną result na True, jeśli hasło jest poprawne
            result = True
            dialog.destroy()
        else:
            messagebox.showerror("Błąd", "Niepoprawne hasło główne.")
            dialog.destroy()

    result = False # Inicjalizuje zmienną result jako False
    dialog = tk.Toplevel() # Tworzy nowe okno dialogowe
    dialog.title("Weryfikacja") # Ustawia tytuł okna dialogowego
    dialog.geometry("295x140") # Ustawia rozmiar okna dialogowego
    dialog.resizable(False, False) # Zapobiega zmianie rozmiaru okna dialogowego
    center_window(dialog) # Wyśrodkowuje okno dialogowe na ekranie
    dialog.transient() # Ustawia okno dialogowe jako podrzędne do głównego okna
    dialog.grab_set() # Ustawia okno dialogowe jako aktywne, blokując interakcję z innymi oknami

    tk.Label(dialog, text="Podaj hasło główne:").pack(pady=10)

    # Tworzy pole tekstowe do wpisania hasła
    password_var = tk.StringVar()
    password_entry = tk.Entry(dialog, textvariable=password_var, show="*")
    password_entry.pack(pady=5)
    password_entry.focus_set()

    # Obsługa klawiszy Enter i Escape
    password_entry.bind("<Return>", lambda _: verify_password())
    password_entry.bind("<Escape>", lambda _: dialog.destroy())

    # Tworzy ramkę na przyciski
    button_frame = tk.Frame(dialog)
    button_frame.pack(pady=10)

    # Przycisk OK i Anuluj
    tk.Button(button_frame, text="OK", command=verify_password).pack(side="left", padx=5)
    tk.Button(button_frame, text="Anuluj", command=dialog.destroy).pack(side="right", padx=5)

    dialog.wait_window() # Czeka na zamknięcie okna dialogowego
    return result

# Funkcja do obliczania siły hasła na podstawie długości i złożoności znaków.
def calculate_password_strength(password):
    length = len(password) # Długość hasła
    has_upper = any(c.isupper() for c in password) # Sprawdza, czy hasło zawiera wielkie litery
    has_lower = any(c.islower() for c in password) # Sprawdza, czy hasło zawiera małe litery
    has_digit = any(c.isdigit() for c in password) # Sprawdza, czy hasło zawiera cyfry
    has_special = any(c in string.punctuation for c in password) # Sprawdza, czy hasło zawiera znaki specjalne

    score = sum([has_upper, has_lower, has_digit, has_special]) # Oblicza wynik na podstawie złożoności znaków

    # Określa siłę hasła na podstawie długości i wyniku
    if length >= 16 and score == 4:
        return "Bardzo silne", "blue"
    elif length >= 12 and score == 4:
        return "Silne", "green"
    elif length >= 8 and score >= 3:
        return "Średnie", "orange"
    else:
        return "Słabe", "red"

# Funkcja do tworzenia pola do wpisywania hasła z opcją pokazania/ukrycia oraz oceną siły hasła.
def create_password_field(parent, show_char="*", with_strength=False):
    # Tworzy ramkę dla pola hasła
    password_frame = tk.Frame(parent)
    password_frame.pack(pady=5)

    # Tworzy ramkę dla pola wpisywania hasła i przycisku
    entry_frame = tk.Frame(password_frame)
    entry_frame.pack()

    # Tworzy pole tekstowe do wpisywania hasła z ograniczeniem długości i opcją ukrywania znaków
    password_entry, password_var = limited_entry(entry_frame, show=show_char)
    password_entry.pack(side="left", padx=5)

    # Funkcja do przełączania widoczności hasła
    def toggle_password_visibility():
        current_show_char = password_entry.cget("show") # Pobiera aktualny znak do ukrywania hasła
        new_show_char = "" if current_show_char == "*" else "*" # Zmienia znak na pusty lub na domyślny
        button_text = "Ukryj" if new_show_char == "" else "Pokaż" # Zmienia tekst przycisku na odpowiedni
        password_entry.config(show=new_show_char) # Ustawia nowy znak do ukrywania hasła
        show_button.config(text=button_text) # Aktualizuje tekst przycisku

    # Tworzy przycisk do przełączania widoczności hasła
    show_button = tk.Button(entry_frame, text="Pokaż", command=toggle_password_visibility)
    show_button.pack(side="left", padx=5)

    strength_label = None # Inicjalizuje etykietę siły hasła jako None

    if with_strength:
        # Dodaje etykietę pokazującą siłę hasła
        strength_label = tk.Label(password_frame, text="Siła hasła: ", fg="gray")
        strength_label.pack(pady=1)

        # Funkcja do aktualizacji etykiety siły hasła na podstawie wpisanego hasła
        def update_strength_label(*_):
            password = password_var.get()
            strength, color = calculate_password_strength(password)
            strength_label.config(text=f"Siła hasła: {strength}", fg=color) # Ustawia tekst i kolor etykiety siły hasła

        password_var.trace_add("write", update_strength_label) # Dodaje śledzenie zmian w zmiennej hasła

    return password_entry, password_var
