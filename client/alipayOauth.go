package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sulrex/gopay/util"
)

const (
	redirectAliOauthURL = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=%s&scope=%s&state=%s&redirect_uri=%s"
	aliGateWay          = "https://openapi.alipay.com/gateway.do"
)

// AliOauth 支付宝网页授权
type AliOauth struct {
	AppID         string // 支付宝分配给开发者的应用ID ps: 查询订单用
	CallbackURL   string // 回调接口
	InsideSandbox bool
	PrivateKey    *rsa.PrivateKey // 私钥
	PublicKey     *rsa.PublicKey  // 公钥
}

// AliOauthToken 支付宝token
type AliOauthToken struct {
	OauthTokenResponse struct { // 排序声明用于验证签名（或：找到截取返回jsonstr的方法)
		AccessToken  string `json:"access_token"`
		AlipayUserID string `json:"alipay_user_id"`
		ExpiresIn    int    `json:"expires_in"`
		ReExpiresIn  int    `json:"re_expires_in"`
		RefreshToken string `json:"refresh_token"`
		UserID       string `json:"user_id"`
	} `json:"alipay_system_oauth_token_response"`

	ErrResponse struct {
		Code    string `json:"code"`
		Msg     string `json:"msg"`
		SubCode string `json:"sub_code"`
		SubMsg  string `json:"sub_msg"`
	} `json:"error_response"`

	Sign string `json:"sign"`
}

// GateWay 获取当前网关
func (t *AliOauth) GateWay() string {
	if t.InsideSandbox {
		return strings.Replace(aliGateWay, "alipay.com", "alipaydev.com", 1)
	}
	return aliGateWay
}

// ToURL 生成URL
func (t *AliOauth) ToURL(payURL string, m map[string]string) string {
	var buf []string
	for k, v := range m {
		buf = append(buf, fmt.Sprintf("%s=%s", k, url.QueryEscape(v)))
	}
	return fmt.Sprintf("%s?%s", payURL, strings.Join(buf, "&"))
}

// Redirect 跳转到网页授权
func (t *AliOauth) Redirect(writer http.ResponseWriter, req *http.Request, redirectURI, scope, state string) {
	gateway := redirectAliOauthURL
	if t.InsideSandbox {
		gateway = strings.Replace(gateway, "alipay.com", "alipaydev.com", 1)
	}
	gateway = fmt.Sprintf(gateway, t.AppID, scope, state, url.QueryEscape(redirectURI))
	http.Redirect(writer, req, gateway, 302)
}

// GetUserAccessToken 通过网页授权的code获得
func (t *AliOauth) GetUserAccessToken(code string) (result AliOauthToken, err error) {

	var m = make(map[string]string)
	m["app_id"] = t.AppID
	m["method"] = "alipay.system.oauth.token"
	m["format"] = "JSON"
	m["charset"] = "utf-8"
	m["sign_type"] = "RSA2"
	m["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	m["version"] = "1.0"
	m["grant_type"] = "authorization_code"
	m["code"] = code
	m["sign"] = t.GenSign(m)

	var response []byte
	req := t.ToURL(t.GateWay(), m)
	response, err = util.HTTPGet(req)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(response, &result)
	if err != nil {
		return result, err
	}

	if result.ErrResponse.Code != "" {
		err = fmt.Errorf("GetUserAccessToken error : errcode=%s , errmsg=%s, submsg=%s", result.ErrResponse.Code, result.ErrResponse.Msg, result.ErrResponse.SubMsg)
		return result, err
	}

	signData, _ := json.Marshal(result.OauthTokenResponse)
	if err = t.CheckSign(string(signData), result.Sign); err != nil {
		return result, fmt.Errorf("返回数据签名不通过 %s", err.Error())
	}

	return result, nil
}

// GenSign 产生签名
func (t *AliOauth) GenSign(m map[string]string) string {
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
	signByte, err := rsa.SignPKCS1v15(rand.Reader, t.PrivateKey, crypto.SHA256, hashByte)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(signByte)
}

// CheckSign 检测签名
func (t *AliOauth) CheckSign(signData, sign string) error {

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
	err = rsa.VerifyPKCS1v15(t.PublicKey, crypto.SHA256, hash, signByte)
	if err != nil {
		return err
	}

	return nil
}
