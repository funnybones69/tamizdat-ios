package vks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// roomfactory.go — server-side room creation for the beacon-assignment
// flow. When a client beacons a PROVIDER (not a specific room) the server
// creates a fresh room on that provider via its API, arms+wakes it, and
// answers the DNS query with the room spec in a TXT record.
//
// Credentials: WB Stream needs the owner Bearer token (no exp, passed as
// -vks-token); Jazz needs nothing (fully anonymous); Telemost and MTS need
// account cookies and are assigned from the armed pool in v1.

// RoomCreator creates a fresh room on the given provider and returns its
// Config. The provider name is one of: telemost, wbstream, jazz, mts.
type RoomCreator func(ctx context.Context, provider string) (Config, error)

// NewRoomCreator builds a RoomCreator from the server config: WB uses the
// owner token; Jazz is anonymous; MTS uses the account cookie header for the
// full create→start→(serve)→DELETE lifecycle (recipe verified live: the
// gw-host + form-urlencoded + quoted x-device-id pattern); Telemost returns
// ErrNoDynamicRoom so the beacon handler falls back to an armed pool room.
func NewRoomCreator(keyHex, ownerToken, mtsCookieHeader string) RoomCreator {
	return func(ctx context.Context, provider string) (Config, error) {
		cfg := Config{Provider: provider, KeyHex: keyHex}
		switch provider {
		case "wbstream":
			if ownerToken == "" {
				return cfg, fmt.Errorf("roomfactory: wbstream needs -vks-token (owner Bearer)")
			}
			roomID, err := createWBRoom(ctx, ownerToken)
			if err != nil {
				return cfg, fmt.Errorf("roomfactory wbstream: %w", err)
			}
			cfg.RoomURL = roomID
			cfg.ProviderToken = ownerToken // the host role needs the owner Bearer
			return cfg, nil
		case "jazz":
			roomID, password, err := createJazzRoom(ctx)
			if err != nil {
				return cfg, fmt.Errorf("roomfactory jazz: %w", err)
			}
			cfg.RoomURL = roomID + ":" + password
			return cfg, nil
		case "mts":
			if mtsCookieHeader == "" {
				return cfg, ErrNoDynamicRoom
			}
			eventID, esid, err := createAndStartMTS(ctx, mtsCookieHeader)
			if err != nil {
				// The one-active-session limit (403 Maximum simultaneous) is
				// expected when a meeting is already running — fall back to
				// the armed pool room in that case.
				log.Printf("roomfactory mts: %v (falling back to pool)", err)
				return cfg, ErrNoDynamicRoom
			}
			cfg.RoomURL = "https://my.mts-link.ru/j/180602801/" + eventID
			// Full lifecycle: delete the meeting when the room is released.
			cfg.CleanupHook = func() {
				dCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if err := deleteMTSEvent(dCtx, mtsCookieHeader, eventID, esid); err != nil {
					log.Printf("roomfactory mts: cleanup %s: %v", eventID, err)
				} else {
					log.Printf("roomfactory mts: cleanup %s deleted", eventID)
				}
			}
			return cfg, nil
		default:
			return cfg, ErrNoDynamicRoom
		}
	}
}

// ErrNoDynamicRoom signals that the provider cannot create rooms on the fly
// (telemost/mts need account cookies) — the caller should assign a room
// from the armed static pool instead.
var ErrNoDynamicRoom = fmt.Errorf("vks: no dynamic room creation for provider")

// createWBRoom creates a fresh WB Stream room with the owner token and
// returns its roomId (verified live: POST /api-room/api/v2/room -> 200).
func createWBRoom(ctx context.Context, ownerToken string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"title":       fmt.Sprintf("tam-%d", time.Now().Unix()%100000),
		"roomType":    "ROOM_TYPE_ALL_ON_SCREEN",
		"roomPrivacy": "ROOM_PRIVACY_FREE",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://stream.wb.ru/api-room/api/v2/room", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux x86_64)")
	type resp struct {
		RoomID string `json:"roomId"`
	}
	r, err := doJSON[resp](ctx, req)
	if err != nil {
		return "", err
	}
	if r.RoomID == "" {
		return "", fmt.Errorf("empty roomId")
	}
	return r.RoomID, nil
}

// createJazzRoom creates a fresh anonymous SaluteJazz room and returns
// "roomId, password" (verified live: POST /room/create-meeting).
func createJazzRoom(ctx context.Context) (string, string, error) {
	body, _ := json.Marshal(map[string]any{
		"title":                             fmt.Sprintf("tam-%d", rand.Intn(100000)),
		"guestEnabled":                      true,
		"lobbyEnabled":                      false,
		"serverVideoRecordAutoStartEnabled": false,
		"sipEnabled":                        false,
		"moderatorEmails":                   []string{},
		"summarizationEnabled":              false,
		"room3dEnabled":                     false,
		"room3dScene":                       "XRLobby",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://bk.salutejazz.ru/room/create-meeting", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Jazz-ClientId", uuid.NewString())
	req.Header.Set("X-Jazz-AuthType", "ANONYMOUS")
	req.Header.Set("X-Client-AuthType", "ANONYMOUS")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux x86_64)")
	type resp struct {
		RoomID   string `json:"roomId"`
		Password string `json:"password"`
	}
	r, err := doJSON[resp](ctx, req)
	if err != nil {
		return "", "", err
	}
	if r.RoomID == "" {
		return "", "", fmt.Errorf("empty roomId")
	}
	return r.RoomID, r.Password, nil
}

// doJSON performs the request and decodes a JSON reply.
func doJSON[T any](ctx context.Context, req *http.Request) (T, error) {
	var out T
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return out, fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// createAndStartMTS creates a quick meeting, its session, and STARTS it —
// the full prepare recipe (verified live): all calls go to the GW host with
// form-urlencoded content-type and the browser's x-device-id (quoted).
// Returns (eventID, esid). A 403 "Maximum simultaneous event sessions"
// surfaces as an error — the caller falls back to the armed pool.
func createAndStartMTS(ctx context.Context, cookieHeader string) (string, string, error) {
	H := map[string]string{
		"Cookie":     cookieHeader,
		"Accept":     "application/json",
		"Referer":    "https://my.mts-link.ru/",
		"x-platform": "Web",
		"x-user-id":  "180602801",
		"x-device-id": `"9e89d185-39da-438d-9f3f-d2273aac5ef7"`,
		"x-device":   "Chrome 153.0.0.0",
		"x-app-version": "3.9.206",
		"x-os":       "Windows 10.0",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
	}
	// 1. create the event
	body, code, err := mtsCall(ctx, http.MethodPost, "https://gw.mts-link.ru/api/event", "type=meeting", H)
	if err != nil || code != 200 && code != 201 {
		return "", "", fmt.Errorf("create event: %d %v %s", code, err, body[:min(80, len(body))])
	}
	var ev struct {
		ID json.Number `json:"id"`
		Data struct {
			ID json.Number `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &ev)
	eventID := ev.ID.String()
	if eventID == "" {
		eventID = ev.Data.ID.String()
	}
	if eventID == "" {
		return "", "", fmt.Errorf("create event: no id in %s", body[:min(100, len(body))])
	}
	// 2. create the session
	body2, code2, err := mtsCall(ctx, http.MethodPost,
		"https://gw.mts-link.ru/api/event/"+eventID+"/session",
		"eventId="+eventID+"&createMethod=personal_account_fast_meeting_web_chats", H)
	_ = body2
	if err != nil || code2 != 200 && code2 != 201 {
		return eventID, "", fmt.Errorf("create session: %d %v", code2, err)
	}
	// find the session id via the event
	body3, code3, err := mtsCall(ctx, http.MethodGet, "https://gw.mts-link.ru/api/event/"+eventID, "", H)
	if err != nil || code3 != 200 {
		return eventID, "", fmt.Errorf("get event: %d %v", code3, err)
	}
	var evd struct {
		EventSessions []struct {
			ID     json.Number `json:"id"`
			Status string      `json:"status"`
		} `json:"eventSessions"`
	}
	if err := json.Unmarshal([]byte(body3), &evd); err != nil || len(evd.EventSessions) == 0 {
		return eventID, "", fmt.Errorf("no sessions: %v", err)
	}
	esid := evd.EventSessions[0].ID.String()
	// 3. START the session (quoted device-id, form-urlencoded — the key!)
	H["content-type"] = "application/x-www-form-urlencoded; charset=utf-8"
	body4, code4, err := mtsCall(ctx, http.MethodPut,
		"https://gw.mts-link.ru/api/eventsession/"+esid+"/start", "", H)
	if err != nil || code4 != 200 {
		return eventID, esid, fmt.Errorf("start session: %d %v %s", code4, err, body4[:min(80, len(body4))])
	}
	return eventID, esid, nil
}

// deleteMTSEvent deletes an MTS meeting (the cleanup half of the lifecycle):
// DELETE on the GW host with the same form-urlencoded pattern -> 204.
func deleteMTSEvent(ctx context.Context, cookieHeader, eventID, esid string) error {
	H := map[string]string{
		"Cookie":     cookieHeader,
		"Accept":     "application/json",
		"Referer":    "https://my.mts-link.ru/",
		"x-platform": "Web",
		"x-user-id":  "180602801",
		"x-device-id": `"9e89d185-39da-438d-9f3f-d2273aac5ef7"`,
		"x-device":   "Chrome 153.0.0.0",
		"x-app-version": "3.9.206",
		"x-os":       "Windows 10.0",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
		"content-type": "application/x-www-form-urlencoded; charset=utf-8",
	}
	_, code, err := mtsCall(ctx, http.MethodDelete, "https://gw.mts-link.ru/api/event/"+eventID, "", H)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("delete: status %d", code)
	}
	return nil
}

// mtsCall performs one HTTP call and returns (body, statusCode, err).
func mtsCall(ctx context.Context, method, url, formBody string, headers map[string]string) (string, int, error) {
	var body []byte
	if formBody != "" {
		body = []byte(formBody)
	} else if method != http.MethodGet {
		body = []byte{}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	if method != http.MethodGet && !strings.Contains(headers["content-type"], "form") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	}
	for k, v := range headers {
		if k == "content-type" {
			req.Header.Set("Content-Type", v)
			continue
		}
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), resp.StatusCode, nil
}
