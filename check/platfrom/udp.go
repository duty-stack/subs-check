package platfrom

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"time"

	"log/slog"

	"github.com/pion/stun/v3"
	"github.com/beck-8/subs-check/config"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
)

// UDPCheckResult 存储 UDP 检测结果
// UDP 表示是否支持 UDP
// ExternalIP 保存从 STUN 服务器获取到的公网 IP
// Error 保存检测过程中发生的错误
type UDPCheckResult struct {
	UDP      bool   // 是否支持UDP
	ExternalIP string // 公网IP地址
	Error      error  // 检测错误
}

// stunConnectionWrapper 包装 net.PacketConn 以实现 stun.Connection 接口
// rc 存储 STUN 服务器地址，la 存储本地地址
type stunConnectionWrapper struct {
	net.PacketConn
	rc net.Addr
	la net.Addr
}

func (c *stunConnectionWrapper) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		slog.Debug("stunConnectionWrapper Read 错误", "error", err)
	}
	return n, err
}

func (c *stunConnectionWrapper) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.rc)
}

func (c *stunConnectionWrapper) LocalAddr() net.Addr {
	return c.la
}

func (c *stunConnectionWrapper) RemoteAddr() net.Addr {
	return c.rc
}

func (c *stunConnectionWrapper) Close() error {
	return c.PacketConn.Close()
}

func (c *stunConnectionWrapper) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

func (c *stunConnectionWrapper) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c *stunConnectionWrapper) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

// CheckUDP 通过代理调用 STUN 服务检测 UDP 连通性
// 遍历 config.GlobalConfig.StunServer 中任意一台，通过即视为支持UDP
func CheckUDP(proxyMap map[string]any) (result UDPCheckResult) {
	defer func() {
		if r := recover(); r != nil {
			name := fmt.Sprintf("%v", proxyMap["name"])
			slog.Error("检测 UDP 时发生 Panic", "proxy", name, "panic", r)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			slog.Error("Panic Stack", "stack", string(buf[:n]))
			result.UDP = false
			result.Error = fmt.Errorf("panic during UDP check: %v", r)
		}
	}()
	result = UDPCheckResult{UDP: false}
	proxyName := fmt.Sprintf("%v", proxyMap["name"])
	// 准备收集日志信息以统一输出，避免进度条干扰
	var serverUsed string
	var attemptCount int
	var extIP string
	var extPort int
	for _, server := range config.GlobalConfig.StunServer {
		// 记录当前测试的 STUN 服务器
		serverUsed = server
		host, portStr, err := net.SplitHostPort(server)
		if err != nil {
			slog.Error("解析 STUN 地址失败", "proxy", proxyName, "server", server, "error", err)
			continue
		}
		portUint, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			slog.Error("解析 STUN 端口失败", "proxy", proxyName, "port", portStr, "error", err)
			continue
		}

		remoteAddr, err := net.ResolveUDPAddr("udp", server)
		if err != nil {
			slog.Error("解析 STUN UDP 地址失败", "proxy", proxyName, "server", server, "error", err)
			continue
		}

		for attempt := 1; attempt <= 5; attempt++ {
			// 记录当前重试次数
			attemptCount = attempt
			adapterIns, err := adapter.ParseProxy(proxyMap)
			if err != nil {
				slog.Error("创建代理适配器失败", "proxy", proxyName, "error", err)
				result.Error = err
				break
			}

			meta := &constant.Metadata{Host: host, DstPort: uint16(portUint)}
			conn, err := adapterIns.DialUDP(meta)
			if err != nil {
				slog.Info("代理UDP拨号失败", "proxy", proxyName, "server", server, "error", err)
				time.Sleep(time.Duration(config.GlobalConfig.Timeout) * time.Millisecond)
				continue
			}
			defer conn.Close()

			stunConn := &stunConnectionWrapper{PacketConn: conn, rc: remoteAddr, la: conn.LocalAddr()}
			client, err := stun.NewClient(stunConn)
			if err != nil {
				slog.Error("创建 STUN 客户端失败", "proxy", proxyName, "error", err)
				conn.Close()
				continue
			}
			defer client.Close()

			msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
			_ = stunConn.SetDeadline(time.Now().Add(time.Duration(config.GlobalConfig.Timeout) * time.Millisecond))

			extIP = ""
			extPort = 0
			err = client.Do(msg, func(evt stun.Event) {
				if evt.Error != nil {
					return
				}
				var xor stun.XORMappedAddress
				if ge := xor.GetFrom(evt.Message); ge != nil {
					return
				}
				extIP = xor.IP.String()
				extPort = xor.Port
			})

			if err == nil && extIP != "" {
				// 检测成功，保存结果并退出
				result.UDP = true
				result.ExternalIP = fmt.Sprintf("%s:%d", extIP, extPort)
				break
			}
			time.Sleep(5 * time.Second)
		}
		if result.UDP {
			break
		}
	}
	// 原子化日志输出，避免其他输出干扰
	block := fmt.Sprintf(
		"\n\n==================== UDP 检查开始 ====================\n"+
			"代理: %s\n"+
			"STUN 服务器: %s\n"+
			"重试次数：%d/%d\n"+
			"ip地址: %s\n"+
			"udp: %t\n"+
			"==================== UDP 检查结束 ====================\n\n",
		proxyName, serverUsed, attemptCount, 5, result.ExternalIP, result.UDP,
	)
	fmt.Print(block)
	return result
}