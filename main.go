package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

// GetAESDecryptedOld decrypts in AES 256 CBC in old, more unsafe way that was used before 0.1.6 version
func GetAESDecryptedOld(encrypted string, PassKeyString string) ([]byte, error) {
	ivString := PassKeyString[:len(PassKeyString)-16]

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(PassKeyString))

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("error 01: block size cant be zero") // block size cannot be zero
	}

	mode := cipher.NewCBCDecrypter(block, []byte(ivString))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return ciphertext, nil
}

// GetAESDecrypted decrypts in AES 256 CBC in correct way
func GetAESDecrypted(encrypted string, PassKeyString string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short, probably old format")
	}

	ivString := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]

	block, err := aes.NewCipher([]byte(PassKeyString))

	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, ivString)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return ciphertext, nil
}

// PKCS5UnPadding pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return src
	}
	length := len(src)
	unpadding := int(src[length-1])

	// If padding is invalid, return original instead of crashing.
	if unpadding <= 0 || unpadding > aes.BlockSize || unpadding > length {
		return src
	}

	return src[:(length - unpadding)]
}

// GetAESEncrypted encrypts text in AES 256 CBC (since 0.1.6 its now safer by not using predictable lv)
func GetAESEncrypted(plaintext string, PassKeyString string) (string, error) {
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
	block, err := aes.NewCipher([]byte(PassKeyString))

	if err != nil {
		return "", err
	}

	ivString := make([]byte, aes.BlockSize)
	_, err = rand.Read(ivString)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(ivString))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(append(ivString, ciphertext...)) //apparently "..." tells go to treat it as not one byte but entire slice

	return str, nil
}

func SaveFile(w fyne.Window, entry *widget.Entry, passKeyEntry *widget.Entry, pathoffile *string) {
	if strings.Contains(*pathoffile, ".txt") {
		saveFileDialog := dialog.NewFileSave(
			func(r fyne.URIWriteCloser, _ error) {
				if r == nil {
					return
				}
				defer r.Close()

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
				f, err := os.OpenFile(*pathoffile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					fmt.Println("error opening file:", err)
					return
				}
				defer f.Close()

				textData := []byte(entry.Text)
				encryptedData, err := GetAESEncrypted(string(textData), PassKeyString)
				if err != nil {
					fmt.Println("error", err)
					return
				}
				f.Write([]byte(encryptedData))
			} else {
				saveFileDialog := dialog.NewFileSave(
					func(r fyne.URIWriteCloser, _ error) {
						if r == nil {
							return
						}
						defer r.Close()

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
					fmt.Println("error while opening")
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
				decoded, _ := base64.StdEncoding.DecodeString(string(data))
				if len(decoded) < aes.BlockSize {
					decryptedFile, err = GetAESDecryptedOld(string(data), PassKeyString)
				} else {
					decryptedFile, err = GetAESDecrypted(string(data), PassKeyString)
					if err != nil {
						decryptedFile, err = GetAESDecryptedOld(string(data), PassKeyString)
					}
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

func SaveList(w fyne.Window, listcontainer *fyne.Container, passKeyEntry *widget.Entry, pathoffile *string) {
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
			f, err := os.OpenFile(*pathoffile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				fmt.Println("error opening file:", err)
				return
			}
			defer f.Close()

			var builder strings.Builder

			for i := 0; i < len(listcontainer.Objects); i += 2 {
				label := listcontainer.Objects[i].(*widget.Label)
				check := listcontainer.Objects[i+1].(*widget.Check)
				builder.WriteString(label.Text + "|" + strconv.FormatBool(check.Checked) + "\n")
			}

			encryptedData, err := GetAESEncrypted(builder.String(), PassKeyString)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			f.Write([]byte(encryptedData))
		} else {
			saveFileDialog := dialog.NewFileSave(
				func(r fyne.URIWriteCloser, _ error) {
					if r == nil {
						return
					}
					defer r.Close()

					var builder strings.Builder

					for i := 0; i < len(listcontainer.Objects); i += 2 {
						label := listcontainer.Objects[i].(*widget.Label)
						check := listcontainer.Objects[i+1].(*widget.Check)
						builder.WriteString(label.Text + "|" + strconv.FormatBool(check.Checked) + "\n")
					}
					encryptedData, err := GetAESEncrypted(builder.String(), PassKeyString)
					if err != nil {
						fmt.Println("error", err)
						return
					}
					r.Write([]byte(encryptedData))
					*pathoffile = r.URI().Path()
					w.SetTitle(*pathoffile)
				}, w)
			saveFileDialog.SetFileName("New encrypted file" + ".tweenklist")
			saveFileDialog.Show()
		}
	}, w)

}

func OpenList(w fyne.Window, listcontainer *fyne.Container, passKeyEntry *widget.Entry, pathoffile *string) {
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
					fmt.Println("error while opening")
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
					decryptedFile, err = GetAESDecryptedOld(string(data), PassKeyString)
					if err != nil {
						fmt.Println("error", err)
						return
					}

				}

				listcontainer.Objects = nil

				lines := strings.Split(string(decryptedFile), "\n")
				for _, line := range lines {
					if line == "" {
						continue
					}
					parts := strings.Split(line, "|")
					label := widget.NewLabel(parts[0])
					check := widget.NewCheck("", func(bool) {})
					if len(parts) > 1 && parts[1] == "true" {
						check.SetChecked(true)
					}
					listcontainer.Add(label)
					listcontainer.Add(check)
				}
				listcontainer.Refresh()

				*pathoffile = r.URI().Path()
				w.SetTitle(*pathoffile)
			}, w)
		}, w)
	openfileDialog.SetFilter(
		storage.NewExtensionFileFilter([]string{".tweenklist"}))
	openfileDialog.Show()
}

func main() {
	//Initializers//
	a := app.New()
	w := a.NewWindow("Tweenk: Encrypted Note App version 0.1.6")

	pathoffile := "" // it was a global variable before but it was useless since this works too
	isTextHidden := false
	kswpdz := false //klucz szyfrowania w pamieci do zapisu (its in polish cuz why not)
	listOn := false
	windowWidth := 1285
	windowHeight := 750

	create_ini, err := os.OpenFile("config.ini", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer create_ini.Close()

	scan_text := bufio.NewScanner(create_ini)
	var isDarkModeOn bool

	for scan_text.Scan() {
		scan_line := scan_text.Text()
		if strings.Contains(scan_line, "dark") {
			isDarkModeOn = true
			a.Settings().SetTheme(theme.DarkTheme())
		} else if strings.Contains(scan_line, "light") {
			isDarkModeOn = false
			a.Settings().SetTheme(theme.LightTheme())
		} else if strings.Contains(scan_line, "saved_pass") {
			fmt.Println("I HATE CUM AND I FUCK YOUR MUM")
		} else {
			create_ini.WriteString("")
		}
	}

	//Notes widgets
	entry1 := widget.NewMultiLineEntry()
	entry1.Wrapping = fyne.TextWrapWord
	entry1.SetPlaceHolder(" ")
	entry1.Move(fyne.NewPos(0, 0))
	//-----------------------------------//

	//TODO widgets
	listcontainer := container.NewVBox()

	entry2 := widget.NewMultiLineEntry()
	entry2.Wrapping = fyne.TextWrapWord
	entry2.SetPlaceHolder("")
	entry2.Move(fyne.NewPos(0, 0))
	entry2.Resize(fyne.NewSize(300, 150))

	button1 := widget.NewButton("Add to list", func() {

		itemlist := widget.NewLabel(entry2.Text)

		check1 := widget.NewCheck("", func(value bool) {

		})

		listcontainer.Add(itemlist)
		listcontainer.Add(check1)
		listcontainer.Refresh()

	})
	button1.Move(fyne.NewPos(700, 100))
	//-----------------------------------//

	//Encryption key//
	passKeyEntry := widget.NewEntry() //this is the value that stores the key provided by user
	passKeyEntry.Password = true
	//-----------------------------------//

	//Shortcuts//
	ctrlS := &desktop.CustomShortcut{KeyName: fyne.KeyS, Modifier: desktop.ControlModifier}
	w.Canvas().AddShortcut(ctrlS, func(shortcut fyne.Shortcut) {
		if !kswpdz {
			passKeyEntry.Text = ""
			passKeyEntry.Refresh()
		}
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
	//Stack, vbox and updating window's content
	stack1 := container.NewStack(entry1)
	vbox1 := container.NewVBox(entry2, listcontainer, button1)

	updateWindow := func() {
		if listOn {
			w.SetContent(vbox1)
		} else {
			w.SetContent(stack1)
		}
	}

	updateWindow()

	//New File
	newfile1 := fyne.NewMenuItem("New", func() {
		pathoffile = ""
		w.SetTitle("Tweenk: Encrypted Note App version 0.1.6")
		entry1.Text = ""
		entry1.Refresh()
		kswpdz = false
		listOn = false
		updateWindow()
	})
	newfile2 := fyne.NewMenuItem("Switch to list/notes", func() {
		pathoffile = ""
		w.SetTitle("Tweenk: Encrypted Note App version 0.1.6")
		kswpdz = false

		if listOn {
			listOn = false
			updateWindow()
		} else {
			listOn = true
			updateWindow()
		}

	})
	//Save file
	savefile1 := fyne.NewMenuItem("Save", func() {
		if !kswpdz {
			passKeyEntry.Text = ""
			passKeyEntry.Refresh()
		}
		SaveFile(w, entry1, passKeyEntry, &pathoffile)
	})

	savefile2 := fyne.NewMenuItem("Save List", func() {
		if !kswpdz {
			passKeyEntry.Text = ""
			passKeyEntry.Refresh()
		}
		SaveList(w, listcontainer, passKeyEntry, &pathoffile)
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
	openfile3 := fyne.NewMenuItem("Open list", func() {
		passKeyEntry.Text = ""
		passKeyEntry.Refresh()
		OpenList(w, listcontainer, passKeyEntry, &pathoffile)
	})

	//Information
	info1 := fyne.NewMenuItem("About Tweenk", func() {
		dialog.ShowInformation("Program information", "Tweenk: Encrypted Note App version 0.1.6 by Maciej Piątek (mpdev@memeware.net)| 2025 |", w)
	})
	//View options
	view1 := fyne.NewMenuItem("Change theme", func() {
		if !isDarkModeOn {
			a.Settings().SetTheme(theme.DarkTheme())
			isDarkModeOn = true
			create_ini.Truncate(1)
			create_ini.Seek(0, 0)
			create_ini.WriteString("dark")
		} else {
			a.Settings().SetTheme(theme.LightTheme())
			isDarkModeOn = false
			create_ini.Truncate(0)
			create_ini.Seek(0, 0)
			create_ini.WriteString("light")
		}
	})
	view2 := fyne.NewMenuItem("Hide text", func() {
		if !isTextHidden {
			entry1.Password = true
			entry2.Password = true
			isTextHidden = true
		} else {
			entry1.Password = false
			entry2.Password = false
			isTextHidden = false
		}
	})
	//Settings
	sett1 := fyne.NewMenuItem("Save encryption key for future saving in this session", func() {
		if !kswpdz {
			kswpdz = true
		} else {
			kswpdz = false
		}

	})

	//-----------------------------------//

	//Menu items//
	menuitem1 := fyne.NewMenu("File", newfile1, newfile2, savefile1, savefile2, openfile1, openfile2, openfile3)
	menuitem2 := fyne.NewMenu("View", view1, view2)
	menuitem3 := fyne.NewMenu("Settings", sett1)
	menuitem4 := fyne.NewMenu("Info", info1)

	mainmenu1 := fyne.NewMainMenu(menuitem1, menuitem2, menuitem3, menuitem4)
	w.SetMainMenu(mainmenu1)

	//-----------------------------------//

	//Window run and resize//
	w.Resize(fyne.NewSize(float32(windowWidth), float32(windowHeight)))
	w.ShowAndRun()

	//-----------------------------------//

	/*What changed in 0.1.6?*/

	// Changed the way lv is used. Before it was the same as password but without last 16 characters but right now its done the way it should be, which is way safer than before.
	// Cleaned up the code a bit.
	// TO FIX IMIDIATELY: Legacy .tweenk file do not fucking work and need to be fixed
	// In the future I plan to make it so the text in that menu changes after you press it but right now it straight up crashes the program so I won't for a while

}
