import tkinter as tk
from tkinter import filedialog, messagebox

# Fungsi Helper 
def clean_text(text):
    return ''.join([char for char in text if char.isalpha()])

# Vigenère Cipher 
def vigenere_encrypt(plaintext, key):
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    key = key * (len(plaintext) // len(key)) + key[:len(plaintext) % len(key)]
    
    ciphertext = ''
    for p, k in zip(plaintext, key):
        shift = ord(k.lower()) - ord('a')
        if p.islower():
            ciphertext += chr((ord(p) - ord('a') + shift) % 26 + ord('a'))
        else:
            ciphertext += chr((ord(p) - ord('A') + shift) % 26 + ord('A'))
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    ciphertext = clean_text(ciphertext)
    key = clean_text(key)
    key = key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)]
    
    plaintext = ''
    for c, k in zip(ciphertext, key):
        shift = ord(k.lower()) - ord('a')
        if c.islower():
            plaintext += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        else:
            plaintext += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
    return plaintext

# Playfair Cipher
def generate_playfair_matrix(key):
    key = clean_text(key)
    matrix = []
    seen = set()
    for char in key:
        if char not in seen and char != 'j':
            seen.add(char)
            matrix.append(char)
    for char in 'abcdefghiklmnopqrstuvwxyz':  # 'j' is omitted
        if char not in seen:
            seen.add(char)
            matrix.append(char)
    
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(plaintext, key):
    plaintext = clean_text(plaintext).replace('j', 'i')
    if len(plaintext) % 2 != 0:
        plaintext += 'x'

    matrix = generate_playfair_matrix(key)
    ciphertext = ""
    
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i+1]
        row1, col1 = find_position(matrix, a.lower())
        row2, col2 = find_position(matrix, b.lower())
        
        encrypted_pair = ""
        if row1 == row2:
            encrypted_pair = matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            encrypted_pair = matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            encrypted_pair = matrix[row1][col2] + matrix[row2][col1]
        
        ciphertext += ''.join([ch.upper() if original.isupper() else ch
                               for ch, original in zip(encrypted_pair, [a, b])])
    
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = ""
    
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        row1, col1 = find_position(matrix, a.lower())
        row2, col2 = find_position(matrix, b.lower())
        
        decrypted_pair = ""
        if row1 == row2:
            decrypted_pair = matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            decrypted_pair = matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            decrypted_pair = matrix[row1][col2] + matrix[row2][col1]
        
        plaintext += ''.join([ch.upper() if original.isupper() else ch
                              for ch, original in zip(decrypted_pair, [a, b])])
    
    return plaintext

# Hill Cipher
def hill_encrypt(plaintext, key_matrix):
    plaintext = clean_text(plaintext)
    if len(plaintext) % 2 != 0:
        plaintext += 'x'

    plaintext_matrix = [[ord(char.lower()) - ord('a')] for char in plaintext]
    ciphertext = ''

    for i in range(0, len(plaintext_matrix), 2):
        vec = plaintext_matrix[i:i+2]
        result = [sum(key_matrix[row][col] * vec[col][0] for col in range(2)) % 26 for row in range(2)]
        ciphertext += ''.join([chr(num + ord('a')).upper() if plaintext[i + j].isupper() else chr(num + ord('a'))
                               for j, num in enumerate(result)])

    return ciphertext

def hill_decrypt(ciphertext, key_matrix_inv):
    ciphertext = clean_text(ciphertext)
    
    ciphertext_matrix = [[ord(char.lower()) - ord('a')] for char in ciphertext]
    plaintext = ''

    for i in range(0, len(ciphertext_matrix), 2):
        vec = ciphertext_matrix[i:i+2]
        result = [sum(key_matrix_inv[row][col] * vec[col][0] for col in range(2)) % 26 for row in range(2)]
        plaintext += ''.join([chr(num + ord('a')).upper() if ciphertext[i + j].isupper() else chr(num + ord('a'))
                              for j, num in enumerate(result)])

    return plaintext

# GUI LayOut
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Program Cipher Encryption and Decryption")
        self.root.geometry("600x400")

        # Main frame
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        # Cipher choice frame
        cipher_frame = tk.LabelFrame(main_frame, text="Pilih Cipher", padx=10, pady=10)
        cipher_frame.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.cipher_var = tk.StringVar(value="vigenere")
        tk.Radiobutton(cipher_frame, text="Vigenère Cipher", variable=self.cipher_var, value="vigenere").pack(anchor="w")
        tk.Radiobutton(cipher_frame, text="Playfair Cipher", variable=self.cipher_var, value="playfair").pack(anchor="w")
        tk.Radiobutton(cipher_frame, text="Hill Cipher", variable=self.cipher_var, value="hill").pack(anchor="w")

        # Message input frame
        message_frame = tk.LabelFrame(main_frame, text="Masukan PlainText", padx=10, pady=10)
        message_frame.grid(row=1, column=0, sticky="nsew")

        self.message_input = tk.Text(message_frame, height=5, width=40)
        self.message_input.pack()

        # Key input frame
        key_frame = tk.LabelFrame(main_frame, text="Masukan key (min 12 characters)", padx=10, pady=10)
        key_frame.grid(row=1, column=1, sticky="nsew")

        self.key_input = tk.Entry(key_frame, width=30)
        self.key_input.pack()

        # File upload button
        tk.Button(main_frame, text="Upload file(.txt)", command=self.upload_file).grid(row=2, column=0, pady=10, sticky="w")

        # Encrypt/Decrypt buttons
        button_frame = tk.Frame(main_frame, padx=10, pady=10)
        button_frame.grid(row=2, column=1, pady=10, sticky="e")
        tk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side="left", padx=5)
        tk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side="left", padx=5)

        # Output area
        output_frame = tk.LabelFrame(main_frame, text="Output", padx=10, pady=10)
        output_frame.grid(row=3, column=0, columnspan=2, sticky="nsew")

        self.output_text = tk.Text(output_frame, height=5, width=80)
        self.output_text.pack()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                self.message_input.delete(1.0, tk.END)
                self.message_input.insert(tk.END, file.read())

    def encrypt(self):
        message = self.message_input.get("1.0", tk.END).strip()
        key = self.key_input.get().strip()
        if len(key) < 12:
            messagebox.showerror("Error", "Key harus lebih dari 12 karakter")
            return

        cipher = self.cipher_var.get()
        if cipher == "vigenere":
            encrypted_message = vigenere_encrypt(message, key)
        elif cipher == "playfair":
            encrypted_message = playfair_encrypt(message, key)
        elif cipher == "hill":
            key_matrix = [[3, 3], [2, 5]] 
            encrypted_message = hill_encrypt(message, key_matrix)
        else:
            encrypted_message = ""

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_message)

    def decrypt(self):
        message = self.message_input.get("1.0", tk.END).strip()
        key = self.key_input.get().strip()
        if len(key) < 12:
            messagebox.showerror("Error", "Key harus lebih dari 12 karakter")
            return

        cipher = self.cipher_var.get()
        if cipher == "vigenere":
            decrypted_message = vigenere_decrypt(message, key)
        elif cipher == "playfair":
            decrypted_message = playfair_decrypt(message, key)
        elif cipher == "hill":
            key_matrix_inv = [[15, 17], [20, 9]] 
            decrypted_message = hill_decrypt(message, key_matrix_inv)
        else:
            decrypted_message = ""

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, decrypted_message)

# Main loop
if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()