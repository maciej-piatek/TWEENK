# Documentation of TWEENK

TWEENK is an encrypted note taking app written in Golang with Fyne GUI.
It uses AES-256 CBC to safely store your notes in files with .tweenk file extension.

It's been programmed in Visual Studio Code 1.103.2 on Windows 10 Pro.

## Encryption
TWEENK uses AES-256 CBC. Program asks for a password everytime you open or save the file, even though this encryption method requires 32 character password for encryption, user doesn't need to input all 32 of them themselves.
Instead even one character is enough since the rest of the characters are filled with zeroes. It is made to make it easier to use it, nobody will remember 32 characters long password. As for LV it is the same as password but 
without last 16 characters.
