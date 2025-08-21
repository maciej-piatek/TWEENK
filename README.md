# TWEENK : Encrypted Note App 
Tweenk is an encrypted note taking app written in Golang. It uses Fyne as its GUI environment. Its a lightweight application made to run on everything that Go and Fyne can run on.
I'm planning to update it frequently and add new useful stuff to it so it will become a powerhouse of a note app in the future.
It uses a custom .tweenk extension and AES-256 CBC encryption.

## Current features:
* Dark/Light mode switch (it saves its settings in an .ini file)
* Text hiding privacy view switch
* Strong AES-256 CBC encryption
* Portability (no need for installation, use it anywhere)
* Ease of use
* Safety (Constantly updating Go and Fyne to the newest versions to avoid bugs and exploits)


## Planned features:
~~1. Dark mode~~ [completed in 0.0.4 version]

2. Web and android support
3. More encryption methods
4. More customization options
5. TODO List
6. Access to recently saved files from a list

## Screencast
![Main_Menu_light](https://github.com/maciej-piatek/TWEENK/blob/main/showcase.gif)

## **About contributing**

1. Feel free to fork the repository if you want to add something new yourself
2. Create a feature branch: `git checkout -b feature-new`
3. Commit changes: `git commit -m "Added feature"`
4. Push to your branch: `git push origin feature-new`
5. Submit a pull request.

## **Stay Connected**
Star the repository if you find it useful or think its cool!  
For support, use [GitHub Issues](https://github.com/maciej-piatek/TWEENK/issues) or contact me via email mpdev@memeware.net.


### Current version as of 12.07.2025 is 0.1.2

# How to install from source:
go install fyne.io/fyne/v2/cmd/fyne@latest

fyne get github.com/maciej-piatek/TWEENK

Also available on sourceforge - https://sourceforge.net/projects/tweenk-encrypted-note-app/
