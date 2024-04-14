import tkinter as tk
from tkinter import filedialog, ttk
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CryptographyApp:
    def __init__(self, master):
        self.master = master
        master.title("Cryptography App")

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill='both', expand=True)

        self.symmetric_frame = tk.Frame(self.notebook)
        self.asymmetric_frame = tk.Frame(self.notebook)
        self.signature_frame = tk.Frame(self.notebook)
        self.hash_frame = tk.Frame(self.notebook)

        self.notebook.add(self.symmetric_frame, text="Symmetric Encryption")
        self.notebook.add(self.asymmetric_frame, text="Asymmetric Encryption")
        self.notebook.add(self.signature_frame, text="Digital Signature")
        self.notebook.add(self.hash_frame, text="Hash")

        self.setup_symmetric_frame()
        self.setup_asymmetric_frame()
        self.setup_signature_frame()
        self.setup_hash_frame()

    def setup_symmetric_frame(self):
        self.label_symmetric = tk.Label(self.symmetric_frame, text="Choose a file:")
        self.label_symmetric.pack()

        self.encrypt_button = tk.Button(self.symmetric_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self.symmetric_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def setup_asymmetric_frame(self):
        self.label_asymmetric = tk.Label(self.asymmetric_frame, text="Choose a file:")
        self.label_asymmetric.pack()

        self.encrypt_button = tk.Button(self.asymmetric_frame, text="Encrypt File", command=self.encrypt_asymmetric)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self.asymmetric_frame, text="Decrypt File", command=self.decrypt_asymmetric)
        self.decrypt_button.pack()

    def setup_signature_frame(self):
        self.label_signature = tk.Label(self.signature_frame, text="Choose a file:")
        self.label_signature.pack()

        self.sign_button = tk.Button(self.signature_frame, text="Sign File", command=self.sign_file)
        self.sign_button.pack()

        self.verify_button = tk.Button(self.signature_frame, text="Verify Signature", command=self.verify_signature)
        self.verify_button.pack()

    def setup_hash_frame(self):
        self.label_hash = tk.Label(self.hash_frame, text="Choose a file:")
        self.label_hash.pack()

        self.hash_button = tk.Button(self.hash_frame, text="Compute Hash", command=self.compute_hash)
        self.hash_button.pack()

    def encrypt_file(self):
        filename = filedialog.askopenfilename()
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)

        with open(filename, "rb") as f:
            plaintext = f.read()

        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open("encrypted.txt", "wb") as f:
            f.write(ciphertext)

        with open("key.txt", "wb") as f:
            f.write(self.key)

        tk.messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_file(self):
        filename = filedialog.askopenfilename()
        with open(filename, "rb") as f:
            ciphertext = f.read()

        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open("decrypted.txt", "wb") as f:
            f.write(plaintext)

        tk.messagebox.showinfo("Success", "File decrypted successfully")

    def encrypt_asymmetric(self):
        filename = filedialog.askopenfilename()
        with open(filename, "rb") as f:
            plaintext = f.read()

        key = RSA.generate(2048)
        cipher = PKCS1_OAEP.new(key)

        ciphertext = cipher.encrypt(plaintext)

        with open("encrypted.txt", "wb") as f:
            f.write(ciphertext)

        with open("key.pem", "wb") as f:
            f.write(key.export_key())

        tk.messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_asymmetric(self):
        filename = filedialog.askopenfilename()
        with open(filename, "rb") as f:
            ciphertext = f.read()

        key = RSA.import_key(open("key.pem").read())
        cipher = PKCS1_OAEP.new(key)

        plaintext = cipher.decrypt(ciphertext)

        with open("decrypted.txt", "wb") as f:
            f.write(plaintext)

        tk.messagebox.showinfo("Success", "File decrypted successfully")

    def sign_file(self):
        filename = filedialog.askopenfilename()
        key = RSA.generate(2048)
        with open(filename, "rb") as f:
            data = f.read()

        hash_value = SHA256.new(data)
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(hash_value)

        with open("signature.txt", "wb") as f:
            f.write(signature)

        with open("key.pem", "wb") as f:
            f.write(key.export_key())

        tk.messagebox.showinfo("Success", "File signed successfully")

    def verify_signature(self):
        filename = filedialog.askopenfilename()
        with open(filename, "rb") as f:
            data = f.read()

        with open("key.pem", "rb") as f:
            key = RSA.import_key(f.read())

        with open("signature.txt", "rb") as f:
            signature = f.read()

        public_key = key.publickey()
        verifier = PKCS1_v1_5.new(public_key)
        hash_value = SHA256.new(data)

        if verifier.verify(hash_value, signature):
            tk.messagebox.showinfo("Success", "Signature is valid")
        else:
            tk.messagebox.showerror("Error", "Signature is not valid")

    def compute_hash(self):
        filename = filedialog.askopenfilename()
        with open(filename, "rb") as f:
            data = f.read()

        hash_value = SHA256.new(data)

        with open("hash.txt", "wb") as f:
            f.write(hash_value.digest())

        tk.messagebox.showinfo("Success", "Hash computed successfully")

root = tk.Tk()
app = CryptographyApp(root)
root.mainloop()
