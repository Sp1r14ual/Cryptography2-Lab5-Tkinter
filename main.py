import tkinter as tk
from tkinter import filedialog, ttk
from Crypto.Cipher import AES, PKCS1_OAEP, DES, ARC4
from Crypto.PublicKey import RSA, ElGamal, DSA, ECC
from Crypto.Signature import DSS, eddsa, pkcs1_15
from Crypto.Hash import SHA256, SHA1, MD5, SHA512
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

        self.algo_label_symmetric = tk.Label(self.symmetric_frame, text="Encryption Algorithm:")
        self.algo_label_symmetric.pack()
        self.algo_combobox_symmetric = ttk.Combobox(self.symmetric_frame, values=["AES", "DES", "RC4"])
        self.algo_combobox_symmetric.pack()

        self.encrypt_button = tk.Button(self.symmetric_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self.symmetric_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def setup_asymmetric_frame(self):
        self.label_asymmetric = tk.Label(self.asymmetric_frame, text="Choose a file:")
        self.label_asymmetric.pack()

        self.algo_label_asymmetric = tk.Label(self.asymmetric_frame, text="Encryption Algorithm:")
        self.algo_label_asymmetric.pack()
        self.algo_combobox_asymmetric = ttk.Combobox(self.asymmetric_frame, values=["RSA"])
        self.algo_combobox_asymmetric.pack()

        self.encrypt_button = tk.Button(self.asymmetric_frame, text="Encrypt File", command=self.encrypt_asymmetric)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self.asymmetric_frame, text="Decrypt File", command=self.decrypt_asymmetric)
        self.decrypt_button.pack()

    def setup_signature_frame(self):
        self.label_signature = tk.Label(self.signature_frame, text="Choose a file:")
        self.label_signature.pack()

        self.algo_label_signature = tk.Label(self.signature_frame, text="Signature Algorithm:")
        self.algo_label_signature.pack()
        self.algo_combobox_signature = ttk.Combobox(self.signature_frame, values=["RSA", "DSA"])
        self.algo_combobox_signature.pack()

        self.sign_button = tk.Button(self.signature_frame, text="Sign File", command=self.sign_file)
        self.sign_button.pack()

        self.verify_button = tk.Button(self.signature_frame, text="Verify Signature", command=self.verify_signature)
        self.verify_button.pack()

    def setup_hash_frame(self):
        self.label_hash = tk.Label(self.hash_frame, text="Choose a file:")
        self.label_hash.pack()

        self.algo_label_hash = tk.Label(self.hash_frame, text="Hash Algorithm:")
        self.algo_label_hash.pack()
        self.algo_combobox_hash = ttk.Combobox(self.hash_frame, values=["SHA-512", "SHA-256", "SHA-1", "MD5"])
        self.algo_combobox_hash.pack()

        self.hash_button = tk.Button(self.hash_frame, text="Compute Hash", command=self.compute_hash)
        self.hash_button.pack()

    def encrypt_file(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_symmetric.get()

        if algorithm == "AES":
            key = get_random_bytes(16)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == "DES":
            key = get_random_bytes(8)
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif algorithm == "RC4":
            key = get_random_bytes(16)
            cipher = ARC4.new(key)

        with open(filename, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open("encrypted.txt", "wb") as f:
            f.write(ciphertext)

        with open("key.txt", "wb") as f:
            f.write(key)

        if algorithm in ("AES", "DES"):
            with open("iv.txt", "wb") as f:
                f.write(iv)

        tk.messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_file(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_symmetric.get()

        with open("key.txt", "rb") as f:
            key = f.read()

        if algorithm in ("AES", "DES"):
            with open("iv.txt", "rb") as f:
                iv = f.read()

        if algorithm == "AES":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == "DES":
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif algorithm == "RC4":
            cipher = ARC4.new(key)

        with open(filename, "rb") as f:
            ciphertext = f.read()

        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open("decrypted.txt", "wb") as f:
            f.write(plaintext)

        tk.messagebox.showinfo("Success", "File decrypted successfully")

    def encrypt_asymmetric(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_asymmetric.get()

        if algorithm == "RSA":
            key = RSA.generate(2048)
            cipher = PKCS1_OAEP.new(key)
        # elif algorithm == "ElGamal":
        #     key = ElGamal.generate(1024, get_random_bytes)
        #     cipher = PKCS1_OAEP.new(key)
        # elif algorithm == "DSA":
        #     key = DSA.generate(1024)
        #     cipher = PKCS1_OAEP.new(key)

        with open(filename, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(plaintext)

        with open("encrypted.txt", "wb") as f:
            f.write(ciphertext)

        with open("key.pem", "wb") as f:
            f.write(key.export_key())

        tk.messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_asymmetric(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_asymmetric.get()

        with open("key.pem", "rb") as f:
            key = RSA.import_key(f.read())

        if algorithm == "RSA":
            cipher = PKCS1_OAEP.new(key)
        # elif algorithm == "ElGamal":
        #     cipher = PKCS1_OAEP.new(key)
        # elif algorithm == "DSA":
        #     cipher = PKCS1_OAEP.new(key)

        with open(filename, "rb") as f:
            ciphertext = f.read()

        plaintext = cipher.decrypt(ciphertext)

        with open("decrypted.txt", "wb") as f:
            f.write(plaintext)

        tk.messagebox.showinfo("Success", "File decrypted successfully")

    def sign_file(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_signature.get()

        if algorithm == "RSA":
            key = RSA.generate(2048)
            signer = pkcs1_15.new(key)
        elif algorithm == "DSA":
            key = DSA.generate(2048)
            signer = DSS.new(key, 'fips-186-3')
        # elif algorithm == "ECC":
        #     key = ECC.generate(curve='ed25519')
        #     signer = eddsa.new(key, 'rfc8032')

        with open(filename, "rb") as f:
            data = f.read()

        hash_value = SHA256.new(data)
        signature = signer.sign(hash_value)

        with open("signature.txt", "wb") as f:
            f.write(signature)

        with open("key.txt", "wb") as f:
            f.write(key.public_key().export_key())

        tk.messagebox.showinfo("Success", "File signed successfully")

    def verify_signature(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_signature.get()

        with open("key.txt", "rb") as f:
            if algorithm == "RSA":
                key = RSA.import_key(f.read())
            elif algorithm == "DSA":
                key = DSA.import_key(f.read())
            # elif algorithm == "ECC":
            #     key = ECC.import_key(f.read())

        with open(filename, "rb") as f:
            data = f.read()

        if algorithm == "RSA":
            verifier = pkcs1_15.new(key)
        elif algorithm == "DSA":
            verifier = DSS.new(key, 'fips-186-3')
        elif algorithm == "ECC":
            verifier = DSS.new(key, 'fips-186-3')

        with open("signature.txt", "rb") as f:
            signature = f.read()

        hash_value = SHA256.new(data)

        try:
            verifier.verify(hash_value, signature)
            tk.messagebox.showinfo("Success", "Signature is valid")
        except ValueError:
            tk.messagebox.showerror("Error", "Signature is not valid")

    def compute_hash(self):
        filename = filedialog.askopenfilename()
        algorithm = self.algo_combobox_hash.get()

        with open(filename, "rb") as f:
            data = f.read()

        if algorithm == "SHA-256":
            hash_value = SHA256.new(data)
        elif algorithm == "SHA-1":
            hash_value = SHA1.new(data)
        elif algorithm == "MD5":
            hash_value = MD5.new(data)
        elif algorithm == "SHA-512":
            hash_value = SHA512.new(data)

        with open("hash.txt", "w") as f:
            f.write(hash_value.hexdigest())

        tk.messagebox.showinfo("Success", "Hash computed successfully")

root = tk.Tk()
app = CryptographyApp(root)
root.mainloop()
