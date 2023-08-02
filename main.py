import base64
from tkinter import *
from tkinter import messagebox


secret_notes_window = Tk()
secret_notes_window.title("Secret Notes")
secret_notes_window.config(padx=80, pady=50)

photo = PhotoImage(file="topsecret.png")
photo_label = Label(image=photo)
photo_label.pack()

#encode ve decode kodlar siteler üzerinden kopyala
#yapıştır yapılmıştır. Daha sonrasında gerekli yerlerdeki
#düzeltmeler yapılmıştır.
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i])+ ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_encrypt_note():
    title = title_input.get()
    note = secret_notes_input.get(1.0, END)
    master_key = enter_masterkey_input.get()

    if title == "" or note == "" or master_key == "":
        messagebox.showwarning("Secret Notes Error!!!", "Error: Please fill in all the blanks!!!")
    else:
        message_encrypted = encode(master_key, note)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_input.delete(0, END)
            secret_notes_input.delete(1.0, END)
            enter_masterkey_input.delete(0, END)

def decrypt_notes():
    message_encrypted = secret_notes_input.get("1.0", END)
    master_secret = enter_masterkey_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showwarning("Secret Notes Error!!!", "Error: Please fill in all the blanks!!!")
    else:
        try:
            decrypt_message = decode(master_secret, message_encrypted)
            secret_notes_input.delete("1.0", END)
            secret_notes_input.insert("1.0", decrypt_message)
        except:
            messagebox.showwarning(title="Secret Notes Error!!!", message="Error: Please enter encrpyted text!!!")

title_label = Label(text="Enter Your Title")
title_label.pack()

title_input = Entry(width=40)
title_input.pack()

secret_notes_label = Label(text="Enter Your Secret Note")
secret_notes_label.pack()

secret_notes_input = Text()
secret_notes_input.pack()
secret_notes_input.config(height=20, width=40)

enter_masterkey_label = Label(text="Enter Master Key")
enter_masterkey_label.pack()

enter_masterkey_input = Entry(width=40)
enter_masterkey_input.pack()

save_button = Button(text="Save & Encrypt", command=save_encrypt_note)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.pack()






secret_notes_window.mainloop()