package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/sulrex/gopay/common"
	"github.com/sulrex/gopay/util"
)

var defaultWechatWebClient *WechatWebClient

// InitWxWebClient ..
func InitWxWebClient(c *WechatWebClient) {
	defaultWechatWebClient = c
}

// DefaultWechatWebClient ..
func DefaultWechatWebClient() *WechatWebClient {
	return defaultWechatWebClient
}

// WechatWebClient 微信公众号支付
type WechatWebClient struct {
	AppID       string // 公众账号ID
	MchID       string // 商户号ID
	SubMch      bool   // 服务商模式
	SubMchID    string // 服务商模式子商户号
	CallbackURL string // 回调地址
	Key         string // 密钥
	PayURL      string // 支付地址
	QueryURL    string // 查询地址
}

// Pay 支付
func (wc *WechatWebClient) Pay(charge *common.Charge) (map[string]string, error) {
	var m = make(map[string]string)
	m["appid"] = wc.AppID
	m["mch_id"] = wc.MchID
	if wc.SubMch {
		m["sub_mch_id"] = wc.SubMchID
	}
	m["nonce_str"] = util.RandomStr()
	m["body"] = TruncatedText(charge.Describe, 32)
	m["out_trade_no"] = charge.TradeNum
	m["total_fee"] = WechatMoneyFeeToString(charge.MoneyFee)
	m["spbill_create_ip"] = util.LocalIP()
	m["notify_url"] = charge.CallbackURL
	m["trade_type"] = "JSAPI"
	m["openid"] = charge.OpenID
	m["sign_type"] = "MD5"

	sign, err := WechatGenSign(wc.Key, m)
	if err != nil {
		return map[string]string{}, err
	}
	m["sign"] = sign

	// 转出xml结构
	xmlRe, err := PostWechat(wc.PayURL, m)
	if err != nil {
		return map[string]string{}, err
	}

	var c = make(map[string]string)
	c["appId"] = wc.AppID
	c["timeStamp"] = fmt.Sprintf("%d", time.Now().Unix())
	c["nonceStr"] = util.RandomStr()
	c["package"] = fmt.Sprintf("prepay_id=%s", xmlRe.PrepayID)
	c["signType"] = "MD5"
	sign2, err := WechatGenSign(wc.Key, c)
	if err != nil {
		return map[string]string{}, errors.New("WechatWeb: " + err.Error())
	}
	c["paySign"] = sign2

	return c, nil
}

// QueryOrder 查询订单
func (wc *WechatWebClient) QueryOrder(tradeNum string) (common.WeChatQueryResult, error) {
	var m = make(map[string]string)
	m["appid"] = wc.AppID
	m["mch_id"] = wc.MchID
	m["out_trade_no"] = tradeNum
	m["nonce_str"] = util.RandomStr()

	sign, err := WechatGenSign(wc.Key, m)
	if err != nil {
		return common.WeChatQueryResult{}, err
	}

	m["sign"] = sign

	return PostWechat("https://api.mch.weixin.qq.com/pay/orderquery", m)
}
