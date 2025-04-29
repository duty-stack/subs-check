package config

import _ "embed"

type Config struct {
	PrintProgress      bool     `yaml:"print-progress"`
	Concurrent         int      `yaml:"concurrent"`
	CheckInterval      int      `yaml:"check-interval"`
	CronExpression     string   `yaml:"cron-expression"`
	SpeedTestUrl       string   `yaml:"speed-test-url"`
	DownloadTimeout    int      `yaml:"download-timeout"`
	MinSpeed           int      `yaml:"min-speed"`
	Timeout            int      `yaml:"timeout"`
	FilterRegex        string   `yaml:"filter-regex"`
	SaveMethod         string   `yaml:"save-method"`
	WebDAVURL          string   `yaml:"webdav-url"`
	WebDAVUsername     string   `yaml:"webdav-username"`
	WebDAVPassword     string   `yaml:"webdav-password"`
	GithubToken        string   `yaml:"github-token"`
	GithubGistID       string   `yaml:"github-gist-id"`
	GithubAPIMirror    string   `yaml:"github-api-mirror"`
	WorkerURL          string   `yaml:"worker-url"`
	WorkerToken        string   `yaml:"worker-token"`
	SubUrlsReTry       int      `yaml:"sub-urls-retry"`
	SubUrls            []string `yaml:"sub-urls"`
	MihomoApiUrl       string   `yaml:"mihomo-api-url"`
	MihomoApiSecret    string   `yaml:"mihomo-api-secret"`
	ListenPort         string   `yaml:"listen-port"`
	RenameNode         bool     `yaml:"rename-node"`
	KeepSuccessProxies bool     `yaml:"keep-success-proxies"`
	OutputDir          string   `yaml:"output-dir"`
	AppriseApiServer   string   `yaml:"apprise-api-server"`
	RecipientUrl       []string `yaml:"recipient-url"`
	NotifyTitle        string   `yaml:"notify-title"`
	SubStorePort       string   `yaml:"sub-store-port"`
	SubStorePath       string   `yaml:"sub-store-path"`
	MihomoOverwriteUrl string   `yaml:"mihomo-overwrite-url"`
	MediaCheck         bool     `yaml:"media-check"`
	Platforms          []string `yaml:"platforms"`
	SuccessLimit       int32    `yaml:"success-limit"`
	NodePrefix         string   `yaml:"node-prefix"`
	EnableWebUI        bool     `yaml:"enable-web-ui"`
	APIKey             string   `yaml:"api-key"`
	GithubProxy        string   `yaml:"github-proxy"`
	CallbackScript     string   `yaml:"callback-script"`
	// 是否开启UDP检测，开启后通过STUN服务器检测UDP连通性
	UDPCheck    bool     `yaml:"udp-check"`
	// STUN 服务器列表，支持多个，任意一个检测通过即视为支持UDP
	StunServer  []string `yaml:"stun-server"`
	// UDP检查通过后附加的标志文本
	UDPFlagText string   `yaml:"udp-flag-text"`
}

var GlobalConfig = &Config{
	// 新增配置，给未更改配置文件的用户一个默认值
	ListenPort:         ":8199",
	NotifyTitle:        "🔔 节点状态更新",
	MihomoOverwriteUrl: "http://127.0.0.1:8199/sub/ACL4SSR_Online_Full.yaml",
	Platforms:          []string{"openai", "youtube", "netflix", "disney", "gemini", "iprisk"},
	// UDP检测默认配置
	UDPCheck:    false,
	StunServer:  []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"},
	UDPFlagText: "UDP",
}

//go:embed config.example.yaml
var DefaultConfigTemplate []byte

var GlobalProxies []map[string]any
