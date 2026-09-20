// Package jazz is the auth provider for SaluteJazz (Sber) VKS rooms.
// Room creation is fully anonymous (no account), which makes jazz the
// strongest fully-anonymous provider in the VKS fallback ladder.
package jazz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/funnybones69/tamizdat/vks/olc/core/auth"
)

const apiBase = "https://bk.salutejazz.ru"

var errAPI = errors.New("jazz api error")

// Provider produces engine credentials for SaluteJazz. It implements
// auth.RoomCreator: rooms are created anonymously (no account needed).
type Provider struct{}

// Engine reports which engine consumes jazz credentials.
func (Provider) Engine() string { return "jazz" }

// DefaultServiceURL returns the well-known Jazz service URL.
func (Provider) DefaultServiceURL() string { return "https://salutejazz.ru" }

// Issue resolves a Jazz room to a signaling connector URL.
//
// cfg.RoomURL accepts either "roomId:password" or a full
// https://salutejazz.ru/calls/<id>?psw=<pwd> link. When empty, a fresh room is
// created anonymously.
func (p Provider) Issue(ctx context.Context, cfg auth.Config) (auth.Credentials, error) {
	roomID, password := splitRoom(cfg.RoomURL)
	if roomID == "" {
		room, err := p.CreateRoom(ctx, cfg)
		if err != nil {
			return auth.Credentials{}, err
		}
		roomID, password = splitRoom(room)
	}
	if roomID == "" {
		return auth.Credentials{}, auth.ErrRoomIDRequired
	}
	conn, err := preconnect(ctx, roomID, password, cfg)
	if err != nil {
		return auth.Credentials{}, err
	}
	return auth.Credentials{
		URL: conn,
		Extra: map[string]string{
			"roomID":   roomID,
			"password": password,
		},
	}, nil
}

// CreateRoom creates a fresh anonymous Jazz room and returns
// "roomId:password".
func (p Provider) CreateRoom(ctx context.Context, cfg auth.Config) (string, error) {
	id, password, err := createMeeting(ctx, cfg)
	if err != nil {
		return "", err
	}
	return id + ":" + password, nil
}

// splitRoom accepts "roomId:password" or a salutejazz.ru/calls/<id>?psw=<pwd>
// link and returns the pair.
func splitRoom(raw string) (roomID, password string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	// full link form
	if strings.Contains(raw, "salutejazz.ru") {
		if i := strings.Index(raw, "/calls/"); i >= 0 {
			raw = raw[i+len("/calls/"):]
		}
		if i := strings.Index(raw, "?psw="); i >= 0 {
			password = raw[i+len("?psw="):]
			raw = raw[:i]
		}
		raw = strings.Trim(raw, "/")
		return raw, password
	}
	// roomId:password form
	if i := strings.Index(raw, ":"); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, ""
}

func anonHeaders() map[string]string {
	return map[string]string{
		"X-Jazz-ClientId":   uuid.New().String(),
		"X-Jazz-AuthType":   "ANONYMOUS",
		"X-Client-AuthType": "ANONYMOUS",
		"Content-Type":      "application/json",
	}
}

func createMeeting(ctx context.Context, cfg auth.Config) (roomID, password string, err error) {
	payload := map[string]any{
		"title":                             cfg.Name,
		"guestEnabled":                      true,
		"lobbyEnabled":                      false,
		"serverVideoRecordAutoStartEnabled": false,
		"sipEnabled":                        false,
		"moderatorEmails":                   []string{},
		"summarizationEnabled":              false,
		"room3dEnabled":                     false,
		"room3dScene":                       "XRLobby",
	}
	var res struct {
		RoomID   string `json:"roomId"`
		Password string `json:"password"`
	}
	if err := post(ctx, apiBase+"/room/create-meeting", payload, &res); err != nil {
		return "", "", fmt.Errorf("%w: create-meeting: %v", errAPI, err)
	}
	if res.RoomID == "" {
		return "", "", fmt.Errorf("%w: create-meeting: empty roomId", errAPI)
	}
	return res.RoomID, res.Password, nil
}

func preconnect(ctx context.Context, roomID, password string, cfg auth.Config) (string, error) {
	payload := map[string]any{
		"password": password,
		"jazzNextMigration": map[string]any{
			"b2bBaseRoomSupport":               true,
			"demoRoomBaseSupport":              true,
			"demoRoomVersionSupport":           2,
			"mediaWithoutAutoSubscribeSupport": true,
			"webinarSpeakerSupport":            true,
			"webinarViewerSupport":             true,
			"sdkRoomSupport":                   true,
			"sberclassRoomSupport":             true,
		},
	}
	var res struct {
		ConnectorURL string `json:"connectorUrl"`
	}
	if err := post(ctx, apiBase+"/room/"+roomID+"/preconnect", payload, &res); err != nil {
		return "", fmt.Errorf("%w: preconnect: %v", errAPI, err)
	}
	if res.ConnectorURL == "" {
		return "", fmt.Errorf("%w: preconnect: empty connectorUrl", errAPI)
	}
	return res.ConnectorURL, nil
}

func post(ctx context.Context, url string, payload map[string]any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range anonHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
