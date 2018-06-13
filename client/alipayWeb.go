package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sulrex/gopay/common"
)

var aliWebClient *AliWebClient

// AliWebClient 支付宝手机网页支付
type AliWebClient struct {
	AppID         string          // 支付宝分配给开发者的应用ID ps: 查询订单用
	CallbackURL   string          // 回调接口
	PrivateKey    *rsa.PrivateKey // 私钥
	PublicKey     *rsa.PublicKey  // 公钥
	InsideSandbox bool            // 沙箱阶段
}

// InitAliWebClient ..
func InitAliWebClient(c *AliWebClient) {
	aliWebClient = c
}

// DefaultAliWebClient 默认支付宝网页支付客户端
func DefaultAliWebClient() *AliWebClient {
	return aliWebClient
}

// GateWay 获取当前网关
func (ac *AliWebClient) GateWay() string {
	if ac.InsideSandbox {
		return strings.Replace(aliGateWay, "alipay.com", "alipaydev.com", 1)
	}
	return aliGateWay
}

// Pay 实现支付下单接口
func (ac *AliWebClient) Pay(charge *common.Charge) (map[string]string, error) {
	m := make(map[string]string)
	m["app_id"] = ac.AppID
	m["method"] = "alipay.trade.wap.pay"
	m["charset"] = "utf-8"
	m["sign_type"] = "RSA2"
	m["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	m["version"] = "1.0"
	m["notify_url"] = ac.CallbackURL
	biz, err := json.Marshal(map[string]string{
		"subject":      charge.Describe,
		"out_trade_no": charge.TradeNum,
		"total_amount": AliyunMoneyFeeToString(charge.MoneyFee),
		"product_code": "QUICK_WAP_WAY",
	})
	if err != nil {
		return map[string]string{}, errors.New("Json Marshal " + err.Error())
	}
	m["biz_content"] = string(biz)
	m["sign"] = ac.GenSign(m)
	return map[string]string{"url": ac.ToURL(ac.GateWay(), m)}, nil
}

// ToURL 生成URL
func (ac *AliWebClient) ToURL(payURL string, m map[string]string) string {
	var buf []string
	for k, v := range m {
		buf = append(buf, fmt.Sprintf("%s=%s", k, url.QueryEscape(v)))
	}
	return fmt.Sprintf("%s?%s", payURL, strings.Join(buf, "&"))
}

// QueryOrder 订单查询 (待处理为新接口)
func (ac *AliWebClient) QueryOrder(outTradeNo string) (common.AliWebQueryResult, error) {
	var m = make(map[string]string)
	m["service"] = "single_trade_query"
	// m["partner"] = ac.PartnerID
	m["_input_charset"] = "utf-8"
	m["out_trade_no"] = outTradeNo
	m["sign"] = ac.GenSign(m)
	m["sign_type"] = "RSA"
	return GetAlipay(ToURL(ac.GateWay(), m))
}

// GenSign 产生签名
func (ac *AliWebClient) GenSign(m map[string]string) string {
	var data []string
	for k, v := range m {
		if v != "" && k != "sign" {
			data = append(data, fmt.Sprintf(`%s=%s`, k, v))
		}
	}
	sort.Strings(data)
	signData := strings.Join(data, "&")

	s := sha256.New()
	_, err := s.Write([]byte(signData))
	if err != nil {
		panic(err)
	}
	hashByte := s.Sum(nil)
	signByte, err := rsa.SignPKCS1v15(rand.Reader, ac.PrivateKey, crypto.SHA256, hashByte)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(signByte)
}

// CheckSign 检测签名
func (ac *AliWebClient) CheckSign(signData, sign string) error {

	signByte, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	s := sha256.New()
	_, err = s.Write([]byte(signData))
	if err != nil {
		return err
	}

	hash := s.Sum(nil)
	err = rsa.VerifyPKCS1v15(ac.PublicKey, crypto.SHA256, hash, signByte)
	if err != nil {
		return err
	}

	return nil
}
