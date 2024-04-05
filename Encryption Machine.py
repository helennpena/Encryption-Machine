import flet as ft
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def main(page: ft.Page):
    page.title = "Encription Machine"
    page.horizontal_alignment = ft.CrossAxisAlignment.START
    page.padding = 50
    page.update()

    page_title = ft.Text("Encryption Machine", size=20, weight=ft.FontWeight.W_600)
    page_subtitle = ft.Text("Enter your text below to encrypt or decrypt a message")
    text_input = ft.TextField(
        label="Input Text", 
        width=500,
        autofocus=True,
        multiline=True, 
        min_lines=1,
        max_lines=4,
        hint_text="Enter your text here...",
    )

    select_text = ft.Text(
        "Select the operation of your choice:",
        size=12,
        color = ft.colors.GREY,
        weight=ft.FontWeight.W_500,
        italic=True
    )

    option1="Encrypt"
    option2= "Decrypt"

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    password = base64.urlsafe_b64encode(kdf.derive(b"H3lenP&n4"))
    
    secret_key = Fernet(password)

    select_options = ft.Dropdown(
        width=200,
        label = "Options",
        options=[
            ft.dropdown.Option(option1),
            ft.dropdown.Option(option2),
        ]
    )

    clipboard_text = ft.Text(
        "Clic the button to copy to clipboard",
        size=12,
        color = ft.colors.BLACK,
        weight=ft.FontWeight.W_400,
    )
    
    message_text = ft.TextField(
        width=500,
        label="Result",
        read_only=True,
        multiline=True,
        min_lines=1,
        max_lines=6,
        border="underline",
        filled=True,
    )

    error_text = ft.Text(
        size=12,
        color=ft.colors.RED,
        weight=ft.FontWeight.W_400,
        italic=True
    )

    

    def submit_clicked(e):
        if text_input.value != "":
            if select_options.value == option1:
                error_text.value = ""
                encrypted_message = str(secret_key.encrypt(text_input.value.encode()))
                encrypted_message = encrypted_message[2:-1]
                message_text.disabled = False
                message_text.value = encrypted_message
                result.width = None
                result.height = None
                page.update()
            elif select_options.value == option2:
                try:
                    error_text.value = ""
                    decrypted_message = str(secret_key.decrypt(text_input.value.encode()))
                    decrypted_message = decrypted_message[2:-1]
                    message_text.disabled = False
                    message_text.value = decrypted_message.replace('\\n', '\n').replace('\\t', '\t')   
                    result.width = None
                    result.height = None
                    page.update()
                except:
                    error_text.value = "Invalid token, please try again"
                    message_text.value = ""
                    message_text.disabled = True
                    page.update()

            else:
                error_text.value = "Error, please select an option to proceed!"
                message_text.disabled = True
                page.update()

        elif text_input.value == "":
            if select_options.value == option1 or select_options.value == option2:
                error_text.value = "Error, the input text can't be blank!"
                message_text.disabled = True
                message_text.value = ""
                page.update()
            else:
                error_text.value = "Error, enter your desired text and select an option!"
                message_text.disabled = True 
                message_text.value = ""
                page.update()
        
        clipboard_button.icon_color=ft.colors.BLUE  
        page.update()

    def copy_clipboard(e):
        page.set_clipboard(message_text.value)
        clipboard_button.icon_color=ft.colors.GREEN  
        page.update()  
        
        
    submit_button = ft.ElevatedButton(
        text="Submit", 
        on_click=submit_clicked,
    )

    clipboard_button = ft.IconButton(
        icon = ft.icons.CONTENT_COPY,
        icon_color=ft.colors.BLUE,
        icon_size= 18,
        tooltip="Copy to clipboard",
        on_click=copy_clipboard
    )

    result = ft.Column([
        ft.Row([clipboard_button, clipboard_text]),
        message_text 
    ],
    height = 0,
    width = 0)

    page.add(
        ft.Container(
            ft.Column([
                page_title, 
                ft.Column([
                    ft.Text("Encryption Machine", size=12),
                ]), 
                page_subtitle, 
                ft.Row(),ft.Row(),
                text_input,
                ft.Row(),ft.Row(),
                select_text, 
                select_options,
                error_text,
                ft.Row(),ft.Row(),
                submit_button,
                result,
            ],
            height= 600,
            spacing=10,
            scroll=ft.ScrollMode.ALWAYS)
        )
    )


ft.app(target=main, view=ft.AppView.WEB_BROWSER)
    
#https://cryptography.io/en/latest/fernet/
#https://www.youtube.com/watch?v=vsLBErLWBhA


