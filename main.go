package main
import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	// "reflect"
	"image/color"
	"gioui.org/app"
	"gioui.org/op"
	// "gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
	"gioui.org/widget"
	"gioui.org/layout"
)
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	add_byte:=[]byte{byte(padding)}
	fmt.Printf("%d more bytes needed.\nByte added: 0x%x.\n",padding,add_byte)
	//PKCS7 Convention
	padText:= bytes.Repeat(add_byte,padding)
	return append(data,padText...)
}
var key_label material.LabelStyle;
var key_input [24]widget.Editor
func show_encryption(){
	key1:=make([]byte,8)
	key2:=make([]byte,8)
	key3:=make([]byte,8)
	for i:=0;i<8;i++{
		if key_input[i].Len()!=1 || key_input[i+8].Len()!=1 || key_input[i+16].Len()!=1{
			key_label.Color=color.NRGBA{R:255,G:0,B:0,A:255}
			key_label.Text="Full Key not entered"
			return
		}
		key1[i]=key_input[i].Text()[0]
		key2[i]=key_input[i+8].Text()[0]
		key3[i]=key_input[i+16].Text()[0]
	}
	key_label.Color=color.NRGBA{R:0,G:0,B:0,A:255}
	key_label.Text="KYS"
	fmt.Println(string(key1))
	fmt.Println(string(key2))
	fmt.Println(string(key3))
}
func window(){
	win:= new(app.Window)
	win.Option(app.Title("3DES-CBC"))
	var ops op.Ops
	var encrypt_button widget.Clickable
	var text_input widget.Editor
	theme:=material.NewTheme()
	key_label=material.Label(theme,20.0,"")
	for i:=0;i<24;i++{
		key_input[i].MaxLen=1
	}
	for {
		switch typ:=win.Event().(type){
			case app.FrameEvent:
				var gtx layout.Context=app.NewContext(&ops,typ)
				if encrypt_button.Clicked(gtx){
					show_encryption()
				}
				layout.Flex{
					Axis:layout.Vertical,
					Spacing:layout.SpaceBetween,
				}.Layout(gtx,
					layout.Rigid(//input section
						func(gtx layout.Context) layout.Dimensions{
							return layout.Flex{
								Axis:layout.Horizontal,
								Spacing:layout.SpaceBetween,
							}.Layout(gtx,
								layout.Rigid(
									func(gtx layout.Context) layout.Dimensions{
										return layout.Flex{
											Axis:layout.Vertical,
											Spacing:layout.SpaceBetween,
										}.Layout(gtx,
											layout.Rigid(
												func(gtx layout.Context) layout.Dimensions{
													return layout.Flex{
														Axis:layout.Horizontal,
														Spacing:layout.SpaceBetween,
													}.Layout(gtx,
														layout.Rigid(
															func(gtx layout.Context) layout.Dimensions{
																return material.Label(theme,20.0,"Text : ").Layout(gtx)
															},
														),
														layout.Rigid(
															func(gtx layout.Context) layout.Dimensions{
																return material.Editor(theme,&text_input,"").Layout(gtx)
															},
														),
													)
												},
											),
											layout.Rigid(
												func(gtx layout.Context) layout.Dimensions{
													var elements [25] layout.FlexChild//one label and 24 input boxes
													elements[0]= layout.Rigid(//label
														func(gtx layout.Context) layout.Dimensions{
															return material.Label(theme,20.0,"Key : ").Layout(gtx)
														},
													)
													for i:=1;i<25;i++{//make input boxes
														elements[i]=layout.Rigid(
															func(gtx layout.Context) layout.Dimensions{
																return widget.Border{
																	Color: color.NRGBA{R:0,G:0,B:0,A:255},
																	Width: unit.Dp(1),
																}.Layout(gtx,
																	func(gtx layout.Context) layout.Dimensions{
																		return material.Editor(theme,&key_input[i-1]," ").Layout(gtx)
																	},
																)
															},
														)
													}
													return layout.Flex{
														Axis:layout.Horizontal,
														Spacing:layout.SpaceBetween,
													}.Layout(gtx, elements[:]...,)
												},
										),
									)
									},
								),
								layout.Rigid(
									func(gtx layout.Context) layout.Dimensions {
										button:=material.Button(theme,&encrypt_button,"Encrypt")
										return button.Layout(gtx)
									},
								),
							)
						},
					),
					layout.Rigid(
						func(gtx layout.Context) layout.Dimensions{
							return key_label.Layout(gtx)
						},
					),
				)
				typ.Frame(gtx.Ops)
			case app.DestroyEvent:
				os.Exit(0)
		}
	}
}
func main() {
	// 24-byte key for Triple DES (3DES)
	key := []byte("1234567890abcdef12345678")
	plaintext := []byte("Lorem ipsum dolor")
	fmt.Printf("Text: %x\n",plaintext)
	paddedtext:=pad(plaintext,des.BlockSize)
	fmt.Printf("Padded: %x\n",paddedtext)
	// Encrypt the plaintext
	block,_:=des.NewTripleDESCipher(key)
	initialization_vector:=make([]byte,des.BlockSize)
	io.ReadFull(rand.Reader,initialization_vector)
	mode:=cipher.NewCBCEncrypter(block,initialization_vector)
	ciphertext:=make([]byte,len(paddedtext))
	mode.CryptBlocks(ciphertext,paddedtext)
	final_cipher:=append(initialization_vector,ciphertext...)
	fmt.Printf("Ciphertext: %x\n",ciphertext)
	fmt.Printf("IV: %x\n",initialization_vector)
	fmt.Printf("Final Cipher: %x\n",final_cipher)
	//
	cipher_text:=make([]byte,len(paddedtext))
	block_des1,_:=des.NewCipher(key[:8])
	block_des2,_:=des.NewCipher(key[8:16])
	block_des3,_:=des.NewCipher(key[16:])
	vector:=append(make([]byte,0),initialization_vector...)
	for i:=0;i<len(paddedtext);i+=des.BlockSize{
		for j:=0;j<des.BlockSize;j++{//cbc
			cipher_text[i+j]=vector[j]^paddedtext[i+j]
			// cipher_text[i+j]=paddedtext[i+j]
		}
		block_des1.Encrypt(cipher_text[i:i+des.BlockSize],cipher_text[i:i+des.BlockSize])
		block_des2.Decrypt(cipher_text[i:i+des.BlockSize],cipher_text[i:i+des.BlockSize])
		block_des3.Encrypt(cipher_text[i:i+des.BlockSize],cipher_text[i:i+des.BlockSize])
		copy(vector,cipher_text[i:i+des.BlockSize])
	}
	full_cipher:=append(initialization_vector,cipher_text...)
	fmt.Printf("3DES-CBC : %x\n",full_cipher)
	//Decrypt
	length:=len(full_cipher)
	original:=make([]byte,length)
	copy(original,full_cipher)
	//decrypt
	for i:=8;i<len(full_cipher);i+=des.BlockSize{
		block_des3.Decrypt(original[i:i+des.BlockSize],original[i:i+des.BlockSize])
		block_des2.Encrypt(original[i:i+des.BlockSize],original[i:i+des.BlockSize])
		block_des1.Decrypt(original[i:i+des.BlockSize],original[i:i+des.BlockSize])
		for j:=0;j<des.BlockSize;j++{//cbc
			original[i+j]=full_cipher[i+j-des.BlockSize]^original[i+j]
		}
	}
	fmt.Printf("Decrypted: %x\n",original)
	fmt.Printf("Original text : %s\n",original[des.BlockSize:length-int(original[length-1])])
	go window()
	app.Main()
}
