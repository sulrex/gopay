package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/milkbobo/gopay/common"
)

var defaultAliAppClient *AliAppClient

// AliAppClient ..
type AliAppClient struct {
	SellerID   string //合作者ID
	AppID      string // 应用ID
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// InitAliAppClient ..
func InitAliAppClient(c *AliAppClient) {
	defaultAliAppClient = c
}

// DefaultAliAppClient 得到默认支付宝app客户端
func DefaultAliAppClient() *AliAppClient {
	return defaultAliAppClient
}

// Pay ..
func (ac *AliAppClient) Pay(charge *common.Charge) (map[string]string, error) {
	var m = make(map[string]string)
	var bizContent = make(map[string]string)
	m["app_id"] = ac.AppID
	m["method"] = "alipay.trade.app.pay"
	m["format"] = "JSON"
	m["charset"] = "utf-8"
	m["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	m["version"] = "1.0"
	m["notify_url"] = charge.CallbackURL
	m["sign_type"] = "RSA"
	bizContent["subject"] = TruncatedText(charge.Describe, 32)
	bizContent["out_trade_no"] = charge.TradeNum
	bizContent["product_code"] = "QUICK_MSECURITY_PAY"
	bizContent["total_amount"] = AliyunMoneyFeeToString(charge.MoneyFee)

	bizContentJSON, err := json.Marshal(bizContent)
	if err != nil {
		return map[string]string{}, errors.New("json.Marshal: " + err.Error())
	}
	m["biz_content"] = string(bizContentJSON)

	m["sign"] = ac.GenSign(m)

	return map[string]string{"orderString": ac.ToURL(m)}, nil
}

// QueryOrder 订单查询
func (ac *AliAppClient) QueryOrder(outTradeNo string) (common.AliWebAppQueryResult, error) {
	var m = make(map[string]string)
	m["method"] = "alipay.trade.query"
	m["app_id"] = ac.AppID
	m["format"] = "JSON"
	m["charset"] = "utf-8"
	m["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	m["version"] = "1.0"
	m["sign_type"] = "RSA"
	bizContent := map[string]string{"out_trade_no": outTradeNo}
	bizContentJSON, err := json.Marshal(bizContent)
	if err != nil {
		return common.AliWebAppQueryResult{}, errors.New("json.Marshal: " + err.Error())
	}
	m["biz_content"] = string(bizContentJSON)
	sign := ac.GenSign(m)
	m["sign"] = sign

	url := fmt.Sprintf("%s?%s", "https://openapi.alipay.com/gateway.do", ac.ToURL(m))

	return GetAlipayApp(url)
}

// GenSign 产生签名
func (ac *AliAppClient) GenSign(m map[string]string) string {
	var data []string

	for k, v := range m {
		if v != "" && k != "sign" {
			data = append(data, fmt.Sprintf(`%s=%s`, k, v))
		}
	}
	sort.Strings(data)
	signData := strings.Join(data, "&")

	s := sha1.New()
	_, err := s.Write([]byte(signData))
	if err != nil {
		panic(err)
	}
	hashByte := s.Sum(nil)
	signByte, err := ac.PrivateKey.Sign(rand.Reader, hashByte, crypto.SHA1)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(signByte)
}

// CheckSign 检测签名
func (ac *AliAppClient) CheckSign(signData, sign string) {
	signByte, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		panic(err)
	}
	s := sha1.New()
	_, err = s.Write([]byte(signData))
	if err != nil {
		panic(err)
	}
	hash := s.Sum(nil)
	err = rsa.VerifyPKCS1v15(ac.PublicKey, crypto.SHA1, hash, signByte)
	if err != nil {
		panic(err)
	}
}

// ToURL ..
func (ac *AliAppClient) ToURL(m map[string]string) string {
	var buf []string
	for k, v := range m {
		buf = append(buf, fmt.Sprintf("%s=%s", k, url.QueryEscape(v)))
	}
	return strings.Join(buf, "&")
}
