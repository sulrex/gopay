package client

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/sulrex/gopay/common"
)

// WechatGenSign 微信签名
func WechatGenSign(key string, m map[string]string) (string, error) {
	var signData []string
	for k, v := range m {
		if v != "" && k != "sign" && k != "key" {
			signData = append(signData, fmt.Sprintf("%s=%s", k, v))
		}
	}

	sort.Strings(signData)
	signStr := strings.Join(signData, "&")
	signStr = signStr + "&key=" + key

	c := md5.New()
	_, err := c.Write([]byte(signStr))
	if err != nil {
		return "", errors.New("WechatGenSign md5.Write: " + err.Error())
	}
	signByte := c.Sum(nil)
	if err != nil {
		return "", errors.New("WechatGenSign md5.Sum: " + err.Error())
	}
	return strings.ToUpper(fmt.Sprintf("%x", signByte)), nil
}

// TruncatedText ..
func TruncatedText(data string, length int) string {
	data = FilterTheSpecialSymbol(data)
	if len([]rune(data)) > length {
		return string([]rune(data)[:length-1])
	}
	return data
}

// FilterTheSpecialSymbol 过滤特殊符号
func FilterTheSpecialSymbol(data string) string {
	// 定义转换规则
	specialSymbol := func(r rune) rune {
		if r == '`' || r == '~' || r == '!' || r == '@' || r == '#' || r == '$' ||
			r == '^' || r == '&' || r == '*' || r == '(' || r == ')' || r == '=' ||
			r == '|' || r == '{' || r == '}' || r == ':' || r == ';' ||
			r == '\'' || r == ',' || r == '\\' || r == '[' || r == ']' || r == '.' || r == '<' ||
			r == '>' || r == '/' || r == '?' || r == '！' ||
			r == '￥' || r == '…' || r == '（' || r == '）' || r == '—' ||
			r == '【' || r == '】' || r == '‘' || r == '；' ||
			r == '：' || r == '”' || r == '“' || r == '"' || r == '。' || r == '，' ||
			r == '、' || r == '？' || r == '%' || r == '+' || r == '_' {
			return ' '
		}
		return r
	}
	data = strings.Map(specialSymbol, data)
	return strings.Replace(data, "\n", " ", -1)
}

// PostWechat 对微信下订单或者查订单
func PostWechat(url string, data map[string]string) (common.WeChatQueryResult, error) {
	var xmlRe common.WeChatQueryResult
	buf := bytes.NewBufferString("")

	for k, v := range data {
		buf.WriteString(fmt.Sprintf("<%s><![CDATA[%s]]></%s>", k, v, k))
	}
	xmlStr := fmt.Sprintf("<xml>%s</xml>", buf.String())
	// fmt.Println(xmlStr)
	re, err := HTTPSC.PostData(url, "text/xml;charset=UTF-8", xmlStr)
	if err != nil {
		return xmlRe, errors.New("HTTPSC.PostData: " + err.Error())
	}

	err = xml.Unmarshal(re, &xmlRe)
	if err != nil {
		return xmlRe, errors.New("xml.Unmarshal: " + err.Error())
	}

	if xmlRe.ReturnCode != "SUCCESS" {
		// 通信失败
		return xmlRe, errors.New("xmlRe.ReturnMsg: " + xmlRe.ReturnMsg)
	}

	if xmlRe.ResultCode != "SUCCESS" {
		// 业务结果失败
		return xmlRe, errors.New("xmlRe.ErrCodeDes: " + xmlRe.ErrCodeDes)
	}
	return xmlRe, nil
}

// GetAlipay 对支付宝者查订单
func GetAlipay(url string) (common.AliWebQueryResult, error) {
	var xmlRe common.AliWebQueryResult

	re, err := HTTPSC.GetData(url)
	if err != nil {
		return xmlRe, errors.New("HTTPSC.PostData: " + err.Error())
	}
	err = xml.Unmarshal(re, &xmlRe)
	if err != nil {
		return xmlRe, errors.New("xml.Unmarshal: " + err.Error())
	}
	return xmlRe, nil
}

// GetAlipayApp 对支付宝者查订单
func GetAlipayApp(urls string) (common.AliWebAppQueryResult, error) {
	var aliPay common.AliWebAppQueryResult

	re, err := HTTPSC.GetData(urls)
	if err != nil {
		return aliPay, errors.New("HTTPSC.PostData: " + err.Error())
	}

	err = json.Unmarshal(re, &aliPay)
	if err != nil {
		panic(fmt.Sprintf("re is %v, err is %v", re, err))
	}

	return aliPay, nil
}

// ToURL ..
func ToURL(payURL string, m map[string]string) string {
	var buf []string
	for k, v := range m {
		buf = append(buf, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s?%s", payURL, strings.Join(buf, "&"))
}

// WechatMoneyFeeToString 微信金额浮点转字符串（issue: 0.03 -> 2 not 3）
// func WechatMoneyFeeToString(moneyFee float64) string {
// 	aDecimal := decimal.NewFromFloat(moneyFee)
// 	bDecimal := decimal.NewFromFloat(100)
// 	return aDecimal.Mul(bDecimal).Truncate(0).String()
// }

// WechatMoneyFeeToString 微信金额浮点转字符串（元*100 -> 分)
func WechatMoneyFeeToString(moneyFee float64) string {
	moneyFee = RoundFloat(moneyFee*100, 0)
	return strconv.FormatFloat(moneyFee, 'f', 0, 64)
}

// AliyunMoneyFeeToString 支付宝金额转字符串
func AliyunMoneyFeeToString(moneyFee float64) string {
	moneyFee = RoundFloat(moneyFee, 2)
	return strconv.FormatFloat(moneyFee, 'f', 2, 64)
}

// RoundFloat 浮点数按精度取整
//Round(±0) = ±0, Round(±Inf) = ±Inf, Round(NaN) = NaN
func RoundFloat(x float64, prec int) float64 {
	var rounder float64
	pow := math.Pow(10, float64(prec))
	intermed := x * pow
	_, frac := math.Modf(intermed)
	x = .5
	if frac < 0.0 {
		x = -.5
	}
	if frac >= x {
		rounder = math.Ceil(intermed)
	} else {
		rounder = math.Floor(intermed)
	}
	return rounder / pow
}
