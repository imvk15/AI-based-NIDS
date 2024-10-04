import tkinter as tk
from tkinter import messagebox
import random
import string
import bcrypt
import pickle
import os

class AuthenticationApp:
    CREDENTIALS_FILE = 'credentials.pkl'

    def __init__(self, root):
        self.root = root
        self.root.title("Authentication Page")
        self.root.geometry("400x500")
        self.root.configure(bg='#F0F4F7')

        self.captcha_value = ""

        self.create_frames()
        self.create_login_widgets()
        self.create_signup_widgets()

        self.frame_login.pack(pady=20)
        self.generate_captcha()

    def create_frames(self):
        self.frame_login = tk.Frame(self.root, bg='#F0F4F7')
        self.frame_signup = tk.Frame(self.root, bg='#F0F4F7')

    def create_login_widgets(self):
        font_style = ('Helvetica', 12)
        button_font_style = ('Helvetica', 12, 'bold')

        tk.Label(self.frame_login, text="Username:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(30, 5))
        self.entry_username = tk.Entry(self.frame_login, font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_username.pack(pady=(0, 20), padx=20)

        tk.Label(self.frame_login, text="Password:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(0, 5))
        self.entry_password = tk.Entry(self.frame_login, show="*", font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_password.pack(pady=(0, 20), padx=20)

        # CAPTCHA Widgets for Login
        self.captcha_label_login = tk.Label(self.frame_login, bg='#F0F4F7', font=('Helvetica', 10), fg='#333333')
        self.captcha_label_login.pack(pady=(5, 10))

        tk.Label(self.frame_login, text="Enter CAPTCHA:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(0, 5))
        self.entry_captcha_login = tk.Entry(self.frame_login, font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_captcha_login.pack(pady=(0, 20), padx=20)

        tk.Button(self.frame_login, text="Sign In", command=self.validate_login, font=button_font_style, bg='#4A90E2', fg='white', relief='flat', activebackground='#357ABD').pack(pady=(10, 5))
        tk.Button(self.frame_login, text="Forgot Password", command=self.forgot_password, font=font_style, bg='#C0C6CC', fg='#333333', relief='flat').pack(pady=(5, 20))
        tk.Button(self.frame_login, text="Switch to Sign Up", command=self.switch_to_signup, font=font_style, bg='#C0C6CC', fg='#333333', relief='flat').pack()

    def create_signup_widgets(self):
        font_style = ('Helvetica', 12)
        button_font_style = ('Helvetica', 12, 'bold')

        tk.Label(self.frame_signup, text="Full Name:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(30, 5))
        self.entry_full_name = tk.Entry(self.frame_signup, font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_full_name.pack(pady=(0, 20), padx=20)

        tk.Label(self.frame_signup, text="Username:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(0, 5))
        self.entry_signup_username = tk.Entry(self.frame_signup, font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_signup_username.pack(pady=(0, 20), padx=20)

        tk.Label(self.frame_signup, text="Password:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(0, 5))
        self.entry_signup_password = tk.Entry(self.frame_signup, show="*", font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_signup_password.pack(pady=(0, 20), padx=20)

        tk.Label(self.frame_signup, text="Confirm Password:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(0, 5))
        self.entry_confirm_password = tk.Entry(self.frame_signup, show="*", font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_confirm_password.pack(pady=(0, 20), padx=20)

        self.captcha_label_signup = tk.Label(self.frame_signup, bg='#F0F4F7', font=('Helvetica', 10), fg='#333333')
        self.captcha_label_signup.pack(pady=(5, 10))

        tk.Label(self.frame_signup, text="Enter CAPTCHA:", bg='#F0F4F7', font=font_style, fg='#333333').pack(pady=(0, 5))
        self.entry_captcha_signup = tk.Entry(self.frame_signup, font=font_style, bg='#FFFFFF', bd=2, relief='solid')
        self.entry_captcha_signup.pack(pady=(0, 20), padx=20)

        tk.Button(self.frame_signup, text="Sign Up", command=self.validate_signup, font=button_font_style, bg='#4A90E2', fg='white', relief='flat', activebackground='#357ABD').pack(pady=(10, 5))
        tk.Button(self.frame_signup, text="Switch to Sign In", command=self.switch_to_login, font=font_style, bg='#C0C6CC', fg='#333333', relief='flat').pack()

    def generate_captcha(self):
        characters = string.ascii_letters + string.digits
        self.captcha_value = ''.join(random.choice(characters) for _ in range(6))
        self.captcha_label_login.config(text=f"Enter this CAPTCHA: {self.captcha_value}")
        self.captcha_label_signup.config(text=f"Enter this CAPTCHA: {self.captcha_value}")

    def hash_password(self, password):
        try:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt).decode()
        except Exception as e:
            messagebox.showerror("Error", f"Error hashing password: {e}")
            return None

    def check_password(self, stored_hash, password):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception as e:
            messagebox.showerror("Error", f"Error checking password: {e}")
            return False

    def load_credentials(self):
        if os.path.exists(self.CREDENTIALS_FILE):
            try:
                with open(self.CREDENTIALS_FILE, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                messagebox.showerror("Error", f"Error loading credentials: {e}")
                return {}
        return {}

    def save_credentials(self, credentials):
        try:
            with open(self.CREDENTIALS_FILE, 'wb') as f:
                pickle.dump(credentials, f)
        except Exception as e:
            messagebox.showerror("Error", f"Error saving credentials: {e}")

    def validate_login(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get()
        captcha_input = self.entry_captcha_login.get().strip()

        credentials = self.load_credentials()

        if captcha_input != self.captcha_value:
            messagebox.showwarning("Login", "Invalid CAPTCHA. Please try again.")
            return

        if username in credentials and self.check_password(credentials[username], password):
            messagebox.showinfo("Login", "Login successful!")
        else:
            messagebox.showwarning("Login", "Invalid username or password.")

    def validate_signup(self):
        username = self.entry_signup_username.get().strip()
        password = self.entry_signup_password.get()
        confirm_password = self.entry_confirm_password.get()
        full_name = self.entry_full_name.get().strip()

        if not all([username, password, confirm_password, full_name]):
            messagebox.showwarning("Sign Up", "Please fill in all fields.")
        elif password != confirm_password:
            messagebox.showwarning("Sign Up", "Passwords do not match.")
        else:
            credentials = self.load_credentials()
            if username in credentials:
                messagebox.showwarning("Sign Up", "Username already exists.")
            else:
                hashed_password = self.hash_password(password)
                if hashed_password:
                    credentials[username] = hashed_password
                    self.save_credentials(credentials)
                    messagebox.showinfo("Sign Up", "Sign Up successful!")

    def forgot_password(self):
        messagebox.showinfo("Forgot Password", "Password recovery instructions sent to your email.")

    def switch_to_login(self):
        self.frame_signup.pack_forget()
        self.frame_login.pack(pady=20)
        self.generate_captcha()  # Refresh CAPTCHA on switching to login

    def switch_to_signup(self):
        self.frame_login.pack_forget()
        self.frame_signup.pack(pady=20)
        self.generate_captcha()  # Generate CAPTCHA on switching to signup

# Create the main window
root = tk.Tk()
app = AuthenticationApp(root)
root.mainloop()
