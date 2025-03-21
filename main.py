import sqlite3
import tkinter as tk
import re

db_path = "some.db"
def table_exists(c, table_name):
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return c.fetchone() is not None  # Повертає True, якщо таблиця існує, інакше False

class User():
    def __init__(self):
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.repeated_password = tk.StringVar()
        self.email = tk.StringVar()

    def reset_username(self):
        self.username.set("")

    def reset_password(self):
        self.password.set("")

    def reset_repeated_password(self):
        self.repeated_password.set("")

    def reset_email(self):
        self.email.set("")

    def reset_all(self):
        self.reset_username()
        self.reset_password()
        self.reset_repeated_password()
        self.reset_email()

    def check_for_existense_username(self, db_path:str, username:str)->bool:
        with sqlite3.connect(db_path) as db:
            c = db.cursor()
            c.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", (username,))
            return c.fetchone()[0]

    def check_has_duplication_email(self, db_path, email: str) -> bool:
        with sqlite3.connect(db_path) as db:
            c = db.cursor()
            c.execute("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", (email,))
            return c.fetchone()[0]

    def register(self):
        """Зберігає дані про користувача у базу даних."""
        with sqlite3.connect(db_path) as db:
            c = db.cursor()
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (self.username.get(), self.password.get(), self.email.get()))

    def login(self, username:str, password:str)->bool:
        """ Перевіряє, чи існує користувач з вказаним username та password у базі даних. Повертає True, якщо такий користувач існує, і False в іншому випадку."""
        with sqlite3.connect(db_path) as db:
            c = db.cursor()
            c.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND password = ?)", (username, password))
            return c.fetchone()[0]

class App():
    def __init__(self, db_path):
        self.win = tk.Tk()
        self.user = User()
        self.db_path = db_path

    def validate_username(self):
        """Дозволяє лише літери, цифри та _, від 3 до 20 символів."""
        return bool(re.fullmatch(r'^[a-zA-Z0-9_]{3,20}$', self.user.username.get()))

    def validate_password(self):
        """Пароль має бути довжиною від 8 до 20 символів, містити хоча б одну літеру та одну цифру."""
        return bool(re.fullmatch(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@#$%^&+=!]{8,20}$', self.user.password.get()))

    def validate_email(self):
        """Проста перевірка коректного формату email."""
        return bool(re.fullmatch(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', self.user.email.get()))

    def start_app(self):
        def center_window(root, width=400, height=300):
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            x = (screen_width - width) // 2
            y = (screen_height - height) // 2
            root.geometry(f"{width}x{height}+{x}+{y}")

        center_window(self.win)
        self.win.title('Якийсь там застосунок')
        self.win.resizable(height=False, width=False)
        self.open_start_win()
        self.win.mainloop()

    def _go_back(self):
        self.user.reset_all()
        self.open_start_win()

    def _clear_window(self):
        for widget in self.win.winfo_children():
            widget.destroy()

    def _show_warning_message(self, text, callback):
        label = tk.Label(self.win, text=text, font=("Arial", 14), wraplength=260, justify="left")
        label.pack(pady=20)
        btn = tk.Button(self.win, text="Спробувати ще раз", command=callback)
        btn.pack(pady=20)

    def _show_success_message(self, text):
        label = tk.Label(self.win, text=text, font=("Arial", 14),  wraplength=260, justify="left")
        label.pack(pady=20)
        btn = tk.Button(self.win, text="Закінчити це все", command=self.win.destroy)
        btn.pack(pady=20)

    def open_start_win(self):
        btn_font = ("Arial", 14, "bold")
        self._clear_window()
        suggestion = tk.Label(self.win, text="Оберіть потрібну дію:", font=("Arial", 18, 'bold'), pady=10)
        sign_in_btn = tk.Button(self.win, text="Увійти", command=self.open_sign_in_win, pady=10, width=15,
                                font=btn_font)
        sign_on_btn = tk.Button(self.win, text="Зареєструватись", command=self.open_sign_on_win, pady=10, width=15,
                                font=btn_font)
        close_btn = tk.Button(self.win, text="Закрити", command=self.win.destroy, pady=10, width=15, font=btn_font)
        suggestion.pack()
        sign_in_btn.place(relx=0.5, rely=0.3, anchor="center")
        sign_on_btn.place(relx=0.5, rely=0.55, anchor="center")
        close_btn.place(relx=0.5, rely=0.8, anchor="center")

    def open_sign_in_win(self):
        self._clear_window()
        label = tk.Label(self.win, text="Введіть Ваше ім'я і пароль!", font=("Arial", 14))
        label.pack(pady=20)

        frame = tk.Frame(self.win, bd=2, relief="ridge")
        btns_frame = tk.Frame(self.win)
        label = tk.Label(frame, text='Username:', bd=10)
        label.grid(row=0, column=0)
        username_field = tk.Entry(frame,textvariable=self.user.username, bg='white', highlightthickness=1)
        username_field.insert(0, "")
        username_field.grid(row=0, column=1)

        label = tk.Label(frame, text='Password:', bd=10)
        label.grid(row=1, column=0)
        password_field = tk.Entry(frame, textvariable=self.user.password, bg='white', highlightthickness=1, show="*")
        password_field.insert(0, "")
        password_field.grid(row=1, column=1)

        frame.pack(pady=10)
        btns_frame.pack(pady=10)

        back_btn = tk.Button(btns_frame, text="Назад", command=self._go_back)
        btn = tk.Button(btns_frame, text="Увійти", command=self.sign_in)
        btn.grid(row=0, column=0, padx=10)
        back_btn.grid(row=0, column=1, padx=10)

    def open_sign_on_win(self):
        self._clear_window()
        label = tk.Label(self.win, text="Введіть Ваші дані!", font=("Arial", 14))
        label.pack(pady=20)

        frame = tk.Frame(self.win, bd=2, relief="ridge")  # рельєф межі фрейму
        btns_frame = tk.Frame(self.win)

        label = tk.Label(frame, text='Username:', bd=10)
        label.grid(row=0, column=0)
        username_field = tk.Entry(frame, textvariable=self.user.username, bg='white', highlightthickness=1)
        username_field.insert(0, "")
        username_field.grid(row=0, column=1)

        label = tk.Label(frame, text='Email:', bd=10)
        label.grid(row=1, column=0)
        email_field = tk.Entry(frame, textvariable=self.user.email, bg='white', highlightthickness=1)
        email_field.insert(0, "")
        email_field.grid(row=1, column=1)

        label = tk.Label(frame, text='Password:', bd=10)
        label.grid(row=2, column=0)
        password_field = tk.Entry(frame, textvariable=self.user.password, bg='white', highlightthickness=1, show="*")
        password_field.insert(0, "")
        password_field.grid(row=2, column=1)

        label = tk.Label(frame, text='Repeat password:', bd=10)
        label.grid(row=3, column=0)
        password_field = tk.Entry(frame, textvariable=self.user.repeated_password, bg='white', highlightthickness=1, show="*")
        password_field.insert(0, "")
        password_field.grid(row=3, column=1)

        frame.pack(pady=10)
        btns_frame.pack(pady=10)

        back_btn = tk.Button(btns_frame, text="Назад", command=self._go_back)
        btn = tk.Button(btns_frame, text="Зареєструватися", command=self.sign_on)
        btn.grid(row=0,column=0, padx=10)
        back_btn.grid(row=0,column=1, padx=10)


    def sign_in(self):
        if not self.validate_username():
            self._clear_window()
            self._show_warning_message("Ім'я має містити лише латинські літери, цифри та знак підкреслення, та має бути довжиною від 3 до 20 символів.", self.open_sign_in_win)
            self.user.reset_username()
        elif not self.user.check_for_existense_username(self.db_path,self.user.username.get()):
            self._clear_window()
            self._show_warning_message(
                "Користувач з таким логіном не зареєстрований.",
                self.open_sign_in_win)
            self.user.reset_all()
        elif self.user.login(self.user.username.get(), self.user.password.get()):
            self._clear_window()
            self._show_success_message("Вітаємо! Ви успішно залогінились!")
        else:
            self._clear_window()
            self._show_warning_message("Невірний пароль!", self.open_sign_in_win)
            self.user.reset_password()

    def sign_on(self):
        if not self.validate_username():
            self._clear_window()
            self._show_warning_message(
                "Ім'я має містити лише латинські літери, цифри та знак підкреслення, та має бути довжиною від 3 до 20 символів.",
                self.open_sign_on_win)
            self.user.reset_username()
        elif not self.validate_email():
            self._clear_window()
            self._show_warning_message(
                "Введіть коректну пошту.",
                self.open_sign_on_win)
            self.user.reset_email()
        elif not self.validate_password():
            self._clear_window()
            self._show_warning_message(
                "Пароль має бути довжиною від 8 до 20 символів, містити хоча б одну латинську літеру та одну цифру.",
                self.open_sign_on_win)
            self.user.reset_password()
            self.user.reset_repeated_password()
        elif self.user.password.get() != self.user.repeated_password.get():
            self._clear_window()
            self._show_warning_message(
                "Пароль має збігатися в обох полях.",
                self.open_sign_on_win)
            self.user.reset_password()
            self.user.reset_repeated_password()
        elif self.user.check_for_existense_username(self.db_path,self.user.username.get()):
            self._clear_window()
            self._show_warning_message("Користувач з таким ім'ям вже зареєстрований!", self.open_sign_on_win)
            self.user.reset_username()
        elif self.user.check_has_duplication_email(self.db_path,self.user.email.get()):
            self._clear_window()
            self._show_warning_message("Користувач з такою поштою вже зареєстрований!", self.open_sign_on_win)
            self.user.reset_email()
        else:
            self.user.register()
            self._clear_window()
            self._show_success_message("Вітаємо! Ви успішно зареєструвалися! ")

with sqlite3.connect(db_path) as db:
    c = db.cursor()
    if not table_exists(c, "users"):
        c.execute("""CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT UNIQUE
            )""")
        db.commit()

some_app = App(db_path)
some_app.start_app()