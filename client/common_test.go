package client

import (
	"fmt"
	"testing"
)

func TestWechatMoneyFeeToString(t *testing.T) {
	for i := 0.00; i < 10; i = i + 0.01 {
		fmt.Println(WechatMoneyFeeToString(i))
	}
}
