# Documentation of TWEENK

TWEENK is an encrypted note taking app written in Golang with Fyne GUI.
It uses AES-256 CBC to safely store your notes in files with .tweenk file extension.

It has been programmed in Visual Studio Code 1.103.2 on Windows 10 Pro.

## How to compile TWEENK on windows
Open terminal in VSCode and type:
1. go install fyne.io/fyne/v2/cmd/fyne@latest
2. fyne get github.com/maciej-piatek/TWEENK
3. fyne package -os windows -icon icon.png 

Now an .exe file was prepared and its ready to use on any windows machine.

## Features
Tweenk consists of a text box where you can input and edit your notes. It acts like any text box in a notepad type program. Above it you can see a menu with four submenus: File, View, Settings and Info.
Window is also resizable and since 0.1.3, text box is too.

![Screenshot_1](https://i.imgur.com/aCbZ6Wn.jpeg)

Clicking on "File" reveals these options:
* New (erases text box)
* New List (opens TODO list creator)
* Save (saves your note to a .tweenk or .txt file depending on your choice to either save an encrypted file or not)
* Open encrypted text (opens a .tweenk file)
* Open plain text (opens .txt file)
* Exit (exits the program)

![Screenshot_2](https://i.ibb.co/Xk3zcZcb/11111.jpg)

Clicking on "View" reveals these options:
* Change theme (changes TWEENK theme from dark to light and vice versa)
* Hide text (hides your notes in a password like format)

![Screenshot_3](https://i.imgur.com/PPyoiqX.jpeg)

Clicking on "Settings" reveals these options:
* Save encryption key for future saving in this session (well it already explains what it does)

![Screenshot_4](https://i.imgur.com/5Moq3PQ.jpeg)

Clicking on "Info" reveals these options:
* About tweenk (shows information about version of the program that you're using and my contact info)

![Screenshot_5](https://i.imgur.com/c6qOGf9.jpeg)

## Encryption
TWEENK uses AES-256 CBC. Program asks for a password every time you open or save the file, even though this encryption method requires 32 character password for encryption, user doesn't need to input all 32 of them themselves.
Instead even one character is enough since the rest of the characters are filled with zeroes. It is made to make it easier to use it, nobody will remember 32 characters long password. As for LV it is the same as password but 
without last 16 characters.
