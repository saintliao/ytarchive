package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/billgraziano/dpapi"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/net/publicsuffix"

	_ "github.com/mattn/go-sqlite3"
)

type LocalState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

var (
	profileDir string
	basePath   string
)

func getBrowserCookiePaths(browserName, profileName string) ([]string, error) {
	browserName = strings.ToLower(browserName)
	if profileName == "" {
		profileName = "Default"
	}

	var cookieFile string

	switch runtime.GOOS {
	case "windows":
		switch browserName {
		case "firefox":
			basePath, _ = os.UserConfigDir()
		default:
			basePath = os.Getenv("LOCALAPPDATA")
		}
	case "linux":
		basePath, _ = os.UserHomeDir()
	case "darwin":
		basePath = filepath.Join(os.Getenv("HOME"), "Library", "Application Support")
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	switch browserName {
	case "chrome":
		cookieFile = "Cookies"
		switch runtime.GOOS {
		case "linux":
			profileDir = ".config/google-chrome"
		case "darwin":
			profileDir = "Google/Chrome"
		default:
			profileDir = filepath.Join("Google", "Chrome", "User Data")
		}
	case "firefox":
		cookieFile = "cookies.sqlite"
		switch runtime.GOOS {
		case "linux":
			profileDir = ".mozilla/firefox"
		case "darwin":
			profileDir = "Firefox"
		default:
			profileDir = filepath.Join("Mozilla", "Firefox", "Profiles")
		}
	case "edge":
		cookieFile = "Cookies"
		profileDir = filepath.Join("Microsoft", "Edge", "User Data")
	case "brave":
		cookieFile = "Cookies"
		profileDir = filepath.Join("BraveSoftware", "Brave-Browser", "User Data")
	default:
		return nil, fmt.Errorf("unsupported browser: %s", browserName)
	}

	profileBasePath := filepath.Join(basePath, profileDir)
	profiles, err := getProfiles(profileBasePath, browserName, profileName)
	if err != nil {
		return nil, err
	}

	var cookiePaths []string
	for _, profile := range profiles {
		var cookiePath string
		switch browserName {
		case "chrome", "edge", "brave":
			if profile == "Default" {
				cookiePath = filepath.Join(profileBasePath, profile, "Network", cookieFile)
			} else {
				cookiePath = filepath.Join(profileBasePath, profile, cookieFile)
			}
		default:
			cookiePath = filepath.Join(profileBasePath, profile, cookieFile)
		}
		if _, err := os.Stat(cookiePath); err == nil {
			cookiePaths = append(cookiePaths, cookiePath)
		} else {
			LogWarn("Cookie file not found: %s", cookiePath)
		}
	}

	return cookiePaths, nil
}

func getProfiles(profileBasePath, browserName, profileName string) ([]string, error) {
	file, err := os.Open(profileBasePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	var profiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			if browserName == "firefox" && strings.Contains(entry.Name(), ".default") {
				profiles = append(profiles, entry.Name())
			} else if browserName != "firefox" {
				if strings.Contains(entry.Name(), profileName) {
					profiles = append(profiles, entry.Name())
				}
			}
		}
	}
	return profiles, nil
}

func getChromiumKey(browserName string) ([]byte, error) {
	localStatePath := filepath.Join(basePath, profileDir, "Local State")
	localStateData, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("could not read Local State file: %v", err)
	}

	var localState LocalState
	err = json.Unmarshal(localStateData, &localState)
	if err != nil {
		return nil, fmt.Errorf("could not parse Local State JSON: %v", err)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode encrypted_key: %v", err)
	}

	if runtime.GOOS == "windows" {
		key, err := dpapi.DecryptBytes(encryptedKey[5:])
		if err != nil {
			return nil, fmt.Errorf("could not decrypt encrypted_key with DPAPI: %v", err)
		}
		return key, nil
	}

	nonce := [24]byte{}
	copy(nonce[:], encryptedKey[3:15])

	chromeFixedKey := []byte("peanuts")

	decryptedKey, ok := secretbox.Open(nil, encryptedKey[15:], &nonce, (*[32]byte)(chromeFixedKey))
	if !ok {
		return nil, errors.New("could not decrypt encrypted_key with secretbox")
	}

	return decryptedKey, nil
}

func getCookies(cookieDBPath, browserName string, chromiumKey []byte) ([]*http.Cookie, error) {
	db, err := sql.Open("sqlite3", cookieDBPath)
	if err != nil {
		return nil, fmt.Errorf("could not open cookie DB: %v", err)
	}
	defer db.Close()

	var rows *sql.Rows

	if browserName == "firefox" {
		rows, err = db.Query("SELECT name, value, host, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
	} else {
		rows, err = db.Query("SELECT name, encrypted_value, host_key, path, expires_utc, is_secure, is_httponly FROM cookies")
	}

	if err != nil {
		return nil, fmt.Errorf("could not query cookies: %v", err)
	}
	defer rows.Close()

	var cookies []*http.Cookie

	for rows.Next() {
		var name, value, host, path string
		var expires int64
		var isSecure, isHTTPOnly bool

		if browserName == "firefox" {
			err = rows.Scan(&name, &value, &host, &path, &expires, &isSecure, &isHTTPOnly)
		} else {
			var encryptedValue []byte
			err = rows.Scan(&name, &encryptedValue, &host, &path, &expires, &isSecure, &isHTTPOnly)
			if err != nil {
				return nil, fmt.Errorf("could not scan cookie row: %v", err)
			}

			if len(encryptedValue) > 0 {
				value, err = decryptChromiumValue(encryptedValue, chromiumKey)
				if err != nil {
					return nil, fmt.Errorf("could not decrypt cookie value: %v", err)
				}
			}
		}

		cookie := &http.Cookie{
			Domain:   host,
			Path:     path,
			Secure:   isSecure,
			Expires:  time.Unix(expires, 0),
			Name:     name,
			Value:    value,
			HttpOnly: isHTTPOnly,
		}

		cookies = append(cookies, cookie)
	}

	return cookies, nil
}

func aes128CBCDecrypt(key, iv, encryptPass []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encryptLen := len(encryptPass)
	if encryptLen < block.BlockSize() {
		return nil, errors.New("length of encrypted password less than block size")
	}

	dst := make([]byte, encryptLen)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, encryptPass)
	dst = pkcs5UnPadding(dst, block.BlockSize())
	return dst, nil
}

func pkcs5UnPadding(src []byte, blockSize int) []byte {
	n := len(src)
	paddingNum := int(src[n-1])
	if n < paddingNum || paddingNum > blockSize {
		return src
	}
	return src[:n-paddingNum]
}

func decryptChromiumValue(encryptedValue, key []byte) (string, error) {
	if len(encryptedValue) < 3 {
		return "", errors.New("password is empty")
	}
	if runtime.GOOS == "windows" {
		nonce := encryptedValue[3:15]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		decrypted, err := aesgcm.Open(nil, nonce, encryptedValue[15:], nil)
		if err != nil {
			return "", err
		}

		return string(decrypted), nil
	} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		iv := []byte{32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32}
		val, err := aes128CBCDecrypt(key, iv, encryptedValue[3:])
		if err != nil {
			return "", err
		}
		return string(val), nil
	}
	return "", errors.New("unknown platform")
}

func (di *DownloadInfo) GetCookieFromBrowser(browser, profile string) (*cookiejar.Jar, int, error) {
	count := 0

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, count, err
	}

	cookiePaths, err := getBrowserCookiePaths(browser, profile)
	if err != nil {
		LogError("Error getting browser cookie paths: %s", err.Error())
		return nil, count, err
	}

	if len(cookiePaths) == 0 {
		LogError("No cookie path found for the browser [%s] and the specified profile [%s], please check if the profile exists or not", browser, profile)
		return nil, count, errors.New("no cookie paths found")
	}

	var chromiumKey []byte
	if browser == "chrome" || browser == "edge" || browser == "brave" {
		chromiumKey, err = getChromiumKey(browser)
		if err != nil {
			LogError("Error getting Chromium key: %v\n", err)
			return nil, count, err
		}
	}
	cookieMap := make(map[string][]*http.Cookie)
	for _, cookiePath := range cookiePaths {
		cookies, err := getCookies(cookiePath, browser, chromiumKey)
		if err != nil {
			LogError("Error getting cookies for %s: %v\n", cookiePath, err)
			continue
		}

		for _, cookie := range cookies {
			if _, ok := cookieMap[cookie.Domain]; !ok {
				cookieMap[cookie.Domain] = make([]*http.Cookie, 0)
			}
			cookieMap[cookie.Domain] = append(cookieMap[cookie.Domain], cookie)
			count++
		}
	}

	if len(cookieMap) > 0 {
		for _, cookies := range cookieMap {
			url, err := url.Parse(fmt.Sprintf("https://%s", cookies[0].Domain))
			if err == nil {
				jar.SetCookies(url, cookies)
				if strings.HasSuffix(url.Host, "youtube.com") {
					di.CookiesURL = url
				}
			}
		}
	}

	return jar, count, nil
}
