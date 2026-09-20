module github.com/anarki/samizdat-ios/mobile

go 1.26.3

// Vendored copy of the tamizdat client/server module (renamed from
// samizdat 2026-05-01, github.com/funnybones69/tamizdat). Replace points
// at ./upstream-tamizdat so we always stay in sync with what the
// production server actually serves.
replace github.com/funnybones69/tamizdat => ./upstream-tamizdat

// iOS-vendor patch of golang.org/x/net to shrink the http2 client's
// transportDefaultConnFlow (1 GiB → 4 MiB) and transportDefaultStreamFlow
// (4 MiB → 256 KiB). Without this, every CONNECT stream advertises a
// 4 MiB receive window — under Speedtest fanout (~64 parallel streams)
// the server can push up to 256 MiB at us before WINDOW_UPDATE, blowing
// past the iOS NEPacketTunnelProvider 50 MB RSS cap. See
// vendor-x-net/http2/transport.go for the patched constants.
replace golang.org/x/net => ./vendor-x-net

// Fork of pion/datachannel used by the VKS room transports (odin SFU DCEP
// quirks, see tamizdat third_party/datachannel). This main-module replace is
// the one that actually applies to the build.
replace github.com/pion/datachannel => ./third_party/datachannel

require (
	github.com/funnybones69/tamizdat v0.0.0-00010101000000-000000000000
	github.com/sagernet/sing v0.8.9
	golang.org/x/mobile v0.0.0-20260410095206-2cfb76559b7b
	golang.org/x/sys v0.45.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	gvisor.dev/gvisor v0.0.0-20260325202830-7644cf3a343c
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20260415201107-50325440f8f2.1 // indirect
	buf.build/go/protovalidate v1.2.0 // indirect
	buf.build/go/protoyaml v0.7.0 // indirect
	cel.dev/expr v0.25.2 // indirect
	codeberg.org/rape4me/kc v0.0.0-20260527075816-a7996790b05b // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bep/debounce v1.2.1 // indirect
	github.com/cbeuw/connutil v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/dennwc/iters v1.2.2 // indirect
	github.com/frostbyte73/core v0.1.1 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/gammazero/deque v1.2.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/cel-go v0.28.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/jxskiss/base62 v1.1.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.3 // indirect
	github.com/lithammer/shortuuid/v4 v4.2.0 // indirect
	github.com/livekit/mageutil v0.0.0-20250511045019-0f1ff63f7731 // indirect
	github.com/livekit/mediatransportutil v0.0.0-20260605212259-862d4a7bcb1e // indirect
	github.com/livekit/protocol v1.50.1 // indirect
	github.com/livekit/psrpc v0.7.2 // indirect
	github.com/magefile/mage v1.17.2 // indirect
	github.com/makiuchi-d/gozxing v0.1.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/nats.go v1.52.0 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/owenewans/owenlivekit/v2 v2.18.2 // indirect
	github.com/pion/datachannel v1.6.0 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/ice/v4 v4.2.7 // indirect
	github.com/pion/interceptor v0.1.45 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.10.2 // indirect
	github.com/pion/sctp v1.10.0 // indirect
	github.com/pion/sdp/v3 v3.0.19 // indirect
	github.com/pion/srtp/v3 v3.0.11 // indirect
	github.com/pion/stun/v3 v3.1.5 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/turn/v5 v5.0.9 // indirect
	github.com/pion/webrtc/v4 v4.2.15 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.68.1 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	github.com/puzpuzpuz/xsync/v4 v4.5.0 // indirect
	github.com/redis/go-redis/v9 v9.20.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/twitchtv/twirp v8.1.3+incompatible // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.72 // indirect
	github.com/xtaci/smux v1.5.57 // indirect
	github.com/zarazaex69/gr v0.1.5 // indirect
	github.com/zarazaex69/j v0.1.0 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260603202125-055de637280b // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.81.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/qr v0.2.0 // indirect
)
