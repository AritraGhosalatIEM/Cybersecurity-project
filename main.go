package main
import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"io"
	"os"
	// "image"
	_ "embed"
	"image/color"
	// "github.com/golang/freetype"
	"gioui.org/app"
	// "gioui.org/f32"
	"gioui.org/font/opentype"
	"gioui.org/op"
	// "gioui.org/op/paint"
	// "gioui.org/op/clip"
	"gioui.org/unit"
	// "gioui.org/text"
	"gioui.org/widget/material"
	"gioui.org/widget"
	"gioui.org/layout"
	//Debugging
	"reflect"
	"fmt"
)
//go:embed agave.ttf
var agave []byte
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	add_byte:=[]byte{byte(padding)}
	fmt.Printf("%d more bytes needed.\nByte added: 0x%x.\n",padding,add_byte)
	//PKCS7 Convention
	padText:= bytes.Repeat(add_byte,padding)
	return append(data,padText...)
}
var key_label material.LabelStyle;
var sh_enc material.ListStyle;
var key_input [24]widget.Editor
var text_input widget.Editor
var scroooooll widget.Scrollbar
var encryption_process[] layout.FlexChild
var theme *material.Theme
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
	// key_label.Text="KYS"
	paddedtext:=pad([]byte(text_input.Text()),des.BlockSize)
	initialization_vector:=make([]byte,des.BlockSize)
	io.ReadFull(rand.Reader,initialization_vector)
	vector:=make([]byte,des.BlockSize)
	copy(vector,initialization_vector)
	xor_with_values:=make([]byte,len(paddedtext))
	encryption_input:=make([]byte,len(paddedtext))
	encryption1_output:=make([]byte,len(paddedtext))
	encryption2_output:=make([]byte,len(paddedtext))
	encryption3_output:=make([]byte,len(paddedtext))
	block_des1,_:=des.NewCipher(key1)
	block_des2,_:=des.NewCipher(key2)
	block_des3,_:=des.NewCipher(key3)
	for i:=0;i<len(paddedtext);i+=des.BlockSize{
		plaintext_blocks:=make([]layout.FlexChild,des.BlockSize)
		xor_with:=make([]layout.FlexChild,des.BlockSize)
		xor_result:=make([]layout.FlexChild,des.BlockSize)
		enc1_result:=make([]layout.FlexChild,des.BlockSize)
		enc2_result:=make([]layout.FlexChild,des.BlockSize)
		enc3_result:=make([]layout.FlexChild,des.BlockSize)
		for j:=0;j<des.BlockSize;j++{
			plaintext_blocks[j]= layout.Rigid(
				func (gtx layout.Context)layout.Dimensions{
					return material.Label(theme,20.0,string(paddedtext[i+j])).Layout(gtx)
				},
			)
			xor_with_values[i+j]=vector[j]
			xor_with[j]= layout.Rigid(
				func (gtx layout.Context)layout.Dimensions{
					return material.Label(theme,20.0,string(xor_with_values[i+j])).Layout(gtx)
				},
			)
			encryption_input[i+j]=vector[j]^paddedtext[i+j]
			xor_result[j]= layout.Rigid(
				func (gtx layout.Context)layout.Dimensions{
					return material.Label(theme,20.0,string(encryption_input[i+j])).Layout(gtx)
				},
			)
		}
		block_des1.Encrypt(encryption1_output[i:i+8],encryption_input[i:i+8])
		block_des2.Decrypt(encryption2_output[i:i+8],encryption1_output[i:i+8])
		block_des3.Encrypt(encryption3_output[i:i+8],encryption2_output[i:i+8])
		copy(vector,encryption3_output[i:i+8])
		for j:=0;j<8;j++{
			enc1_result[j]= layout.Rigid(
				func (gtx layout.Context)layout.Dimensions{
					return material.Label(theme,20.0,string(encryption1_output[i+j])).Layout(gtx)
				},
			)
			enc2_result[j]= layout.Rigid(
				func (gtx layout.Context)layout.Dimensions{
					return material.Label(theme,20.0,string(encryption2_output[i+j])).Layout(gtx)
				},
			)
			enc3_result[j]= layout.Rigid(
				func (gtx layout.Context)layout.Dimensions{
					return material.Label(theme,20.0,string(encryption3_output[i+j])).Layout(gtx)
				},
			)
		}
		var block_process layout.FlexChild=layout.Rigid(//display of encryption for each block
			func(gtx layout.Context)layout.Dimensions{
				return layout.Flex{
					Axis:layout.Horizontal,
					Spacing:layout.SpaceBetween,
				}.Layout(gtx,
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return widget.Border{
								Color:color.NRGBA{R:0,G:0,B:0,A:255},
								Width:unit.Dp(1),
							}.Layout(gtx,
								func(gtx layout.Context)layout.Dimensions{
									return layout.Flex{
										Axis:layout.Vertical,
										Spacing:layout.SpaceBetween,
									}.Layout(gtx, plaintext_blocks...,)
								},
							)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return material.Label(theme,20.0,"⊕").Layout(gtx)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return widget.Border{
								Color:color.NRGBA{R:0,G:0,B:0,A:255},
								Width:unit.Dp(1),
							}.Layout(gtx,
								func(gtx layout.Context)layout.Dimensions{
									return layout.Flex{
										Axis:layout.Vertical,
										Spacing:layout.SpaceBetween,
									}.Layout(gtx,xor_with...,)
								},
							)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return material.Label(theme,20.0,"=").Layout(gtx)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return widget.Border{
								Color:color.NRGBA{R:0,G:0,B:0,A:255},
								Width:unit.Dp(1),
							}.Layout(gtx,
								func(gtx layout.Context)layout.Dimensions{
									return layout.Flex{
										Axis:layout.Vertical,
										Spacing:layout.SpaceBetween,
									}.Layout(gtx,xor_result...,)
								},
							)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return widget.Border{
								Color:color.NRGBA{R:0,G:0,B:0,A:255},
								Width:unit.Dp(1),
							}.Layout(gtx,
								func(gtx layout.Context)layout.Dimensions{
									return layout.Flex{
										Axis:layout.Vertical,
										Spacing:layout.SpaceBetween,
									}.Layout(gtx,enc1_result...,)
								},
							)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return widget.Border{
								Color:color.NRGBA{R:0,G:0,B:0,A:255},
								Width:unit.Dp(1),
							}.Layout(gtx,
								func(gtx layout.Context)layout.Dimensions{
									return layout.Flex{
										Axis:layout.Vertical,
										Spacing:layout.SpaceBetween,
									}.Layout(gtx,enc2_result...,)
								},
							)
						},
					),
					layout.Rigid(
						func(gtx layout.Context)layout.Dimensions{
							return widget.Border{
								Color:color.NRGBA{R:0,G:0,B:0,A:255},
								Width:unit.Dp(1),
							}.Layout(gtx,
								func(gtx layout.Context)layout.Dimensions{
									return layout.Flex{
										Axis:layout.Vertical,
										Spacing:layout.SpaceBetween,
									}.Layout(gtx,enc3_result...,)
								},
							)
						},
					),
				)
			},
		)
		encryption_process=append(encryption_process,block_process)
	}
}
func window(){
	win:= new(app.Window)
	win.Option(app.Title("3DES-CBC"))
	var ops op.Ops
	var encrypt_button widget.Clickable
	text_input.SingleLine=false
	theme=material.NewTheme()
	monospace,_:=opentype.ParseCollection(agave)
	// theme.Face=monospace
	fmt.Println(reflect.TypeOf(monospace))
	key_label=material.Label(theme,20.0,"")
	var lay_list layout.List
	lay_list.Axis=layout.Vertical
	lay_list.Alignment=layout.Start
	wid_list:=widget.List{
		scroooooll,
		lay_list,
	}
	sh_enc=material.List(theme,&wid_list)
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
																	Color:color.NRGBA{R:0,G:0,B:0,A:255},
																	Width:unit.Dp(1),
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
					layout.Rigid(
						func(gtx layout.Context) layout.Dimensions{
							return sh_enc.Layout(gtx,1,func(gtx layout.Context,index int) layout.Dimensions{
								return layout.Flex{
									Axis:layout.Vertical,
									Spacing:layout.SpaceBetween,
								}.Layout(gtx,encryption_process...,)
							})
						},
					),
				)
				// paint.ColorOp{Color: color.NRGBA{R: 0x80, A: 0xFF}}.Add(gtx.Ops)
				// var path clip.Path
				// path.Begin(gtx.Ops)
				// path.Move(f32.Pt(10,10))
				// path.Line(f32.Pt(20,20))
				// paint.FillShape(gtx.Ops,color.NRGBA{R: 0x80, A: 0xFF},
				// 	clip.Stroke{
				// 		Path:path.End(),
				// 		Width:4,
				// 	}.Op(),
				// )
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
