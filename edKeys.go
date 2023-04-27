package edKeys

import(
	"crypto/aes"
    "crypto/cipher"
	"crypto/x509"
    "encoding/pem"
	"fmt"
	"io/ioutil"
R	"math/rand"
	"path/filepath"
	"os"
	"strings"
	"time"
	"golang.org/x/crypto/scrypt"
	
)

var (
    lowerCharSet   = "abcdedfghijklmnopqrst"
    upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    specialCharSet = "!@#$%&*"
    numberSet      = "0123456789"
    allCharSet     = lowerCharSet + upperCharSet + specialCharSet + numberSet
)


func GenerateED25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error){
	PublicKey,PrivateKey, err := ed25519.GenerateKey(rand.Reader) 
	fmt.Println(err)
	return PublicKey, PrivateKey, err


}


func Encrypt(password, data []byte) ([]byte, error) {
    key, salt, err := DeriveKey(password, nil)
    if err != nil {
        return nil, err
    }
    blockCipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(blockCipher)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return nil, err
    }
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    ciphertext = append(ciphertext, salt...)
    return ciphertext, nil
}
func Decrypt(password, data []byte) (string, error) {
    salt, data := data[len(data)-32:], data[:len(data)-32]
    key, _, err := DeriveKey(password, salt)
    if err != nil {
        return "", err
    }
    blockCipher, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(blockCipher)
    if err != nil {
        return "", err
    }
    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

func DeriveKey(password, salt []byte) ([]byte, []byte, error) {
    if salt == nil {
        salt = make([]byte, 32)
        if _, err := rand.Read(salt); err != nil {
            return nil, nil, err
        }
    }
    key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
    if err != nil {
        return nil, nil, err
    }
    return key, salt, nil
}


func createPass() string{
    
    minSpecialChar := 32
    minNum := 32
    minUpperCase := 32
    passwordLength := 128
    return generatePassword(passwordLength, minSpecialChar, minNum, minUpperCase)
	
}

func generatePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) string {
    var password strings.Builder
	R.Seed(time.Now().Unix())
    //Set special character
    for i := 0; i < minSpecialChar; i++ {
        random := R.Intn(len(specialCharSet))
        password.WriteString(string(specialCharSet[random]))
    }

    //Set numeric
    for i := 0; i < minNum; i++ {
        random := R.Intn(len(numberSet))
        password.WriteString(string(numberSet[random]))
    }

    //Set uppercase
    for i := 0; i < minUpperCase; i++ {
        random := R.Intn(len(upperCharSet))
        password.WriteString(string(upperCharSet[random]))
    }

    remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
    for i := 0; i < remainingLength; i++ {
        random := R.Intn(len(allCharSet))
        password.WriteString(string(allCharSet[random]))
    }
    inRune := []rune(password.String())
	R.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})
	return string(inRune)
}


func WriteTemporaryKeyFile(dirName, file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	path :=filepath.Join(dirName, "keys")
	theFile:=filepath.Join(path, file)
	fmt.Println("Saving Key to File", theFile)
	_, err := os.Stat(path)
	if err !=nil{
		 if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
			return "Can not create directory ", err
		}
	}else{
		// Atomic write: create a temporary hidden file first
		// then move it into place. TempFile assigns mode 0600.
	     err :=  ioutil.WriteFile(theFile, content, 0644)
		if err != nil {
			return "Could not create Key file", err
		}
		
		return "Wrote Key to File", nil
	}
	
	return "", err
}

func EncodeEDKey(privateKey ed25519.PrivateKey) (string) {
    x509Encoded,err:= x509.MarshalPKCS8PrivateKey(privateKey)
	if err !=nil{
		fmt.Println("Error Encoding Key ", err)
	}
    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})


    return string(pemEncoded)
}

func DecodeEDKey(pemEncoded string) (ed25519.PrivateKey) {
    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, _ := x509.ParsePKCS8PrivateKey(x509Encoded)
	edKey, _ :=privateKey.(ed25519.PrivateKey)
    
    return edKey
}
func StoreEDKey ( key ed25519.PrivateKey, auth, dirName string) (string, error){
keyJson := EncodeEDKey(key)
keyjson, err := Encrypt([]byte(auth), []byte(keyJson))
	if err != nil {
		return "PubKey", err
	}
	fmt.Println("PubKey")
	wKey2File, err := WriteTemporaryKeyFile(dirName, "onionKey", keyjson)
	fmt.Println(wKey2File)
	//os.Rename(tmpName, fileName)
	return "onionKey", err
}

func GetEDKey(filename, auth string) (ed25519.PrivateKey, error) {
	// Load the key from the keystore and decrypt its contents
	keyjson, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	key, err := Decrypt([]byte(auth), []byte(keyjson))
	if err != nil {
		fmt.Println(err)
	}
	
	prvKey:= DecodeEDKey(key)
	// Make sure we're really operating on the requested key (no swap attacks)
	
	return prvKey, nil
}