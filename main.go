package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var PassKeyString string

// GetAESDecrypted decrypts in AES 256 CBC
func GetAESDecrypted(encrypted string, PassKeyString string) ([]byte, error) {
	ivString := PassKeyString[:len(PassKeyString)-16]
	enckey := PassKeyString
	iv := ivString

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(enckey))

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("error 01: block size cant be zero") // block size cannot be zero
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return ciphertext, nil
}

// PKCS5UnPadding pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

// GetAESEncrypted encrypts text in AES 256 CBC
func GetAESEncrypted(plaintext string, PassKeyString string) (string, error) {
	ivString := PassKeyString[:len(PassKeyString)-16]
	enckey := PassKeyString
	iv := ivString

	var plainTextBlock []byte
	length := len(plaintext)

	if length%16 != 0 {
		extendBlock := 16 - (length % 16)
		plainTextBlock = make([]byte, length+extendBlock)
		copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plainTextBlock = make([]byte, length)
	}

	copy(plainTextBlock, plaintext)
	block, err := aes.NewCipher([]byte(enckey))

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(ciphertext)

	return str, nil
}

func SaveFile(w fyne.Window, entry *widget.Entry, passKeyEntry *widget.Entry, pathoffile *string) {
	if strings.Contains(*pathoffile, ".txt") {
		saveFileDialog := dialog.NewFileSave(
			func(r fyne.URIWriteCloser, _ error) {
				if r == nil {
					return
				}
				textData := []byte(entry.Text)
				r.Write([]byte(textData))
				*pathoffile = r.URI().Path()
				w.SetTitle(*pathoffile)
			}, w)
		saveFileDialog.SetFileName(filepath.Base(*pathoffile))
		saveFileDialog.Show()

	} else {
		dialog.ShowForm("Type the encryption key (password)", "OK", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Encryption Key", passKeyEntry),
		}, func(confirm bool) {
			if !confirm {
				fmt.Println("error while saving")
				return
			}
			/* This checks if your encryption key is 32 bit long, if it isn't it will either cut out unnecesary data or add zeroes to fill the gap */
			PassKeyString := passKeyEntry.Text
			if len(PassKeyString) > 32 {
				subtract := len(PassKeyString) - 32
				PassKeyString = PassKeyString[:len(PassKeyString)-subtract]
			} else if len(PassKeyString) < 32 {
				substract := 32 - len(PassKeyString)
				addtable := make([]int, substract)
				add := ""
				for _, num := range addtable {
					add += strconv.Itoa(num)
				}
				PassKeyString = PassKeyString + add
			}

			if *pathoffile != "" {
				f, err := os.OpenFile(*pathoffile, os.O_WRONLY|os.O_CREATE, 0666)
				if err != nil {
					fmt.Println("error opening file:", err)
					return
				}
				defer f.Close()
				f.WriteString(entry.Text)
			} else {
				saveFileDialog := dialog.NewFileSave(
					func(r fyne.URIWriteCloser, _ error) {
						if r == nil {
							return
						}
						textData := []byte(entry.Text)
						encryptedData, err := GetAESEncrypted(string(textData), PassKeyString)
						if err != nil {
							fmt.Println("error", err)
							return
						}
						r.Write([]byte(encryptedData))
						*pathoffile = r.URI().Path()
						w.SetTitle(*pathoffile)
					}, w)
				saveFileDialog.SetFileName("New encrypted file" + ".tweenk")
				saveFileDialog.Show()
			}
		}, w)
	}

}

func OpenFile(w fyne.Window, entry *widget.Entry, passKeyEntry *widget.Entry, pathoffile *string) {
	openfileDialog := dialog.NewFileOpen(
		func(r fyne.URIReadCloser, _ error) {
			if r == nil {
				fmt.Println("error")
				return
			}
			dialog.ShowForm("Type the encryption key (password)", "OK", "Cancel", []*widget.FormItem{
				widget.NewFormItem("Encryption Key", passKeyEntry),
			}, func(confirm bool) {
				if !confirm {
					fmt.Println("error while saving")
					return
				}
				/* This checks if your encryption key is 32 bit long, if it isn't it will either cut out unnecesary data or add zeroes to fill the gap */
				PassKeyString := passKeyEntry.Text
				if len(PassKeyString) > 32 {
					subtract := len(PassKeyString) - 32
					PassKeyString = PassKeyString[:len(PassKeyString)-subtract]
				} else if len(PassKeyString) < 32 {
					substract := 32 - len(PassKeyString)
					addtable := make([]int, substract)
					add := ""
					for _, num := range addtable {
						add += strconv.Itoa(num)
					}
					PassKeyString = PassKeyString + add
				}

				data, err := io.ReadAll(r)
				if err != nil {
					fmt.Println("error")
					return
				}

				decryptedFile, err := GetAESDecrypted(string(data), PassKeyString)
				if err != nil {
					fmt.Println("error", err)
					return
				}

				entry.SetText(string(decryptedFile))
				*pathoffile = r.URI().Path()
				w.SetTitle(*pathoffile)
			}, w)
		}, w)
	openfileDialog.SetFilter(
		storage.NewExtensionFileFilter([]string{".tweenk"}))
	openfileDialog.Show()
}

func OpenPlainFile(w fyne.Window, entry *widget.Entry, pathoffile *string) {
	openfileDialog := dialog.NewFileOpen(
		func(r fyne.URIReadCloser, _ error) {
			if r == nil {
				fmt.Println("error")
				return
			}

			data, err := io.ReadAll(r)
			if err != nil {
				fmt.Println("error", err)
				return
			}

			entry.SetText(string(data))
			*pathoffile = r.URI().Path()
			w.SetTitle(*pathoffile)
		}, w)

	openfileDialog.SetFilter(
		storage.NewExtensionFileFilter([]string{".txt"}))
	openfileDialog.Show()
}

func main() {
	//Initializers//
	a := app.New()
	w := a.NewWindow("Tweenk: Encrypted Note App version 0.1.0")
	pathoffile := "" // it was a global variable before but it was useless since this works too
	isDarkModeOn := false
	isTextHidden := false
	entry1 := widget.NewMultiLineEntry()
	entry1.SetPlaceHolder(" ")
	entry1.Move(fyne.NewPos(0, 0))
	entry1.Resize(fyne.NewSize(1280, 720))
	//-----------------------------------//

	//Checks for richtext

	//-----------------------------------//

	//Encryption key//
	passKeyEntry := widget.NewEntry() //this is the value that stores the key provided by user
	passKeyEntry.Password = true
	//-----------------------------------//

	//Shortcuts//
	ctrlS := &desktop.CustomShortcut{KeyName: fyne.KeyS, Modifier: desktop.ControlModifier}
	w.Canvas().AddShortcut(ctrlS, func(shortcut fyne.Shortcut) {
		passKeyEntry.Text = ""
		passKeyEntry.Refresh()
		SaveFile(w, entry1, passKeyEntry, &pathoffile)
	})
	ctrlO := &desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: desktop.ControlModifier}
	w.Canvas().AddShortcut(ctrlO, func(shortcut fyne.Shortcut) {
		passKeyEntry.Text = ""
		passKeyEntry.Refresh()
		OpenFile(w, entry1, passKeyEntry, &pathoffile)
	})

	//-----------------------------------//

	/*Menu subitems*/
	//New file
	newfile1 := fyne.NewMenuItem("New", func() {
		pathoffile = ""
		w.SetTitle("Tweenk: Encrypted Note App version 0.1.0")
		entry1.Text = ""
		entry1.Refresh()
	})
	//Save file
	savefile1 := fyne.NewMenuItem("Save", func() {
		passKeyEntry.Text = ""
		passKeyEntry.Refresh()
		SaveFile(w, entry1, passKeyEntry, &pathoffile)
	})
	//Open file
	openfile1 := fyne.NewMenuItem("Open encrypted text", func() {
		passKeyEntry.Text = ""
		passKeyEntry.Refresh()
		OpenFile(w, entry1, passKeyEntry, &pathoffile)
	})
	openfile2 := fyne.NewMenuItem("Open plain text", func() {
		passKeyEntry.Text = ""
		passKeyEntry.Refresh()
		OpenPlainFile(w, entry1, &pathoffile)
	})

	//Information
	info1 := fyne.NewMenuItem("About Tweenk", func() {
		dialog.ShowInformation("Program information", "Tweenk: Encrypted Note App version 0.1.0 by Maciej Piątek (mpdev@memeware.net)| 2025 |", w)
	})
	//View options
	view1 := fyne.NewMenuItem("Change theme", func() {
		if !isDarkModeOn {
			a.Settings().SetTheme(theme.DarkTheme())
			isDarkModeOn = true
		} else {
			a.Settings().SetTheme(theme.LightTheme())
			isDarkModeOn = false
		}
	})
	view2 := fyne.NewMenuItem("Hide text", func() {
		if !isTextHidden {
			entry1.Password = true
			isTextHidden = true
		} else {
			entry1.Password = false
			isTextHidden = false
		}
	})

	//-----------------------------------//

	//Menu items//
	menuitem1 := fyne.NewMenu("File", newfile1, savefile1, openfile1, openfile2)
	menuitem2 := fyne.NewMenu("Info", info1)
	menuitem3 := fyne.NewMenu("View", view1, view2)
	mainmenu1 := fyne.NewMainMenu(menuitem1, menuitem3, menuitem2)
	w.SetMainMenu(mainmenu1)

	//-----------------------------------//

	//Size and run//
	NWLtest := container.NewWithoutLayout(entry1)
	w.SetContent(NWLtest)
	w.Resize(fyne.NewSize(1285, 750))

	NWLtest.Resize(w.Canvas().Size())
	w.ShowAndRun()
	//-----------------------------------//

	/*What changed in 0.1.0?*/
	//Rearanged menu items
	//Updated to latest fyne version (fyne 2.6.1)

}
