package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

var counter int = 1
var pathoffile string
var PassString string

// This function decrypts AES 256 CBC
func GetAESDecrypted(encrypted string, passString string) ([]byte, error) {
	ivString := passString[:len(passString)-16]
	enckey := passString
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
		return nil, fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return ciphertext, nil
}

// PKCS5UnPadding  pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

// GetAESEncrypted encrypts text in AES 256 CBC
func GetAESEncrypted(plaintext string, passString string) (string, error) {
	ivString := passString[:len(passString)-16]
	enckey := passString
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

func main() {
	a := app.New()
	w := a.NewWindow("Tweenk: Encrypted Note App version 0.0.2")
	entry1 := widget.NewMultiLineEntry()
	entry1.SetPlaceHolder(" ")
	entry1.Move(fyne.NewPos(0, 0))
	entry1.Resize(fyne.NewSize(500, 500))

	//Encryption//
	passEntry := widget.NewEntry() //this is the value that stores the passord you type

	passitem := []*widget.FormItem{
		widget.NewFormItem("Password", passEntry),
	}

	//-----------------------------------//

	//Menu subitems//
	newfile1 := fyne.NewMenuItem("New", func() {
		pathoffile = ""
		w.SetTitle("Tweenk")
		entry1.Text = ""
		entry1.Refresh()
	})
	savefile1 := fyne.NewMenuItem("Save", func() {
		dialog.ShowForm("Type the password", "OK", "Cancel", passitem, func(confirm bool) {
			if confirm {
				PassString = passEntry.Text
				/* This checks if your encryption key is 32 bit long, if it isn't it will either cut out unnecesary data or add zeroes to fill the gap */
				if len(PassString) > 32 {
					subtract := len(PassString) - 32
					PassString = PassString[:len(PassString)-subtract]
				} else if len(PassString) < 32 {
					substract := 32 - len(PassString)
					addtable := make([]int, substract)
					add := ""
					for _, num := range addtable {
						add += strconv.Itoa(num)
					}

					PassString = PassString + add
					fmt.Println("It was more than 32 so it is it now: " + PassString)
				}
				/*---------------------------------------------------------------------*/

				if len(PassString) == 32 {
					if pathoffile != "" {
						f, err := os.OpenFile(pathoffile, os.O_WRONLY|os.O_CREATE, 0666)
						if err != nil {

						}
						defer f.Close()
						f.WriteString(entry1.Text)
					} else {
						saveFileDialog := dialog.NewFileSave(
							func(r fyne.URIWriteCloser, _ error) {
								textData := []byte(entry1.Text)
								encryptedData, err := GetAESEncrypted(string(textData), PassString)
								if 1 == 0 {
									fmt.Println(err)
								}
								r.Write([]byte(encryptedData))
								pathoffile = r.URI().Path()
								w.SetTitle(pathoffile)
							}, w)
						saveFileDialog.SetFileName("New encrypted file" + strconv.Itoa(counter-1) + ".tweenk")
						saveFileDialog.Show()
					}
				} else {
					fmt.Println("nwm")
				}
			} else {
				fmt.Println("skibidi toilet")
			}
		}, w)

	})
	openfile1 := fyne.NewMenuItem("Open", func() {
		openfileDialog := dialog.NewFileOpen(
			func(r fyne.URIReadCloser, _ error) {
				dialog.ShowForm("Type the password", "OK", "Cancel", passitem, func(confirm bool) {
					if confirm {
						PassString = passEntry.Text
						/* This checks if your encryption key is 32 bit long, if it isn't it will either cut out unnecesary data or add zeroes to fill the gap */

						if len(PassString) > 32 {
							subtract := len(PassString) - 32
							PassString = PassString[:len(PassString)-subtract]
						} else if len(PassString) < 32 {
							substract := 32 - len(PassString)
							addtable := make([]int, substract)
							add := ""
							for _, num := range addtable {
								add += strconv.Itoa(num)
							}

							/*---------------------------------------------------------------------*/

							PassString = PassString + add
							fmt.Println("It was more than 32 so it is it now: " + PassString)
						}

						if len(PassString) == 32 {
							data, _ := ioutil.ReadAll(r)
							result := fyne.NewStaticResource("name", data)
							decryptedFile, err := GetAESDecrypted(string(result.StaticContent), PassString)
							if 1 == 0 {
								fmt.Println(err)
							}
							entry1.SetText(string(decryptedFile))
							pathoffile = r.URI().Path()
							w.SetTitle(pathoffile)
						} else {
							fmt.Println(len(PassString))
						}
					} else {
						fmt.Println("skibidi fortnite")
					}
				}, w)

			}, w)
		openfileDialog.SetFilter(
			storage.NewExtensionFileFilter([]string{".tweenk"}))
		openfileDialog.Show()
	})
	info1 := fyne.NewMenuItem("About Tweenk", func() {
		dialog.ShowInformation("Program information", "Tweenk: Encrypted Note App version 0.0.2 by Maciej Piątek | 2025 |", w)
	})
	//-----------------------------------//

	//Menu items//
	menuitem1 := fyne.NewMenu("File", newfile1, savefile1, openfile1)
	menuitem2 := fyne.NewMenu("Info", info1)
	mainmenu1 := fyne.NewMainMenu(menuitem1, menuitem2)
	w.SetMainMenu(mainmenu1)
	w.SetContent(
		container.NewWithoutLayout(
			entry1,
		),
	)
	//-----------------------------------//
	w.Resize(fyne.NewSize(500, 500))
	w.ShowAndRun()
}

func GetPassword() string {
	return PassString
}
