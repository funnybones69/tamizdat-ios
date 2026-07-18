package wgturnclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workersPerGroup  = 12
	defaultCycleSecs = 36000
	quotaRetryBase   = 10 * time.Second
	quotaRetryMax    = 60 * time.Second
	quotaRetrySpread = 10 * time.Second
)

type configBroker struct {
	ch       chan<- string
	sent     atomic.Bool
	inFlight atomic.Bool
}

func (b *configBroker) claim() bool {
	return b != nil && !b.sent.Load() && b.inFlight.CompareAndSwap(false, true)
}

func (b *configBroker) complete(delivered bool) {
	if b == nil {
		return
	}
	if delivered {
		b.sent.Store(true)
	}
	b.inFlight.Store(false)
}

// rearmAfterBondLoss allows exactly one future worker to become a config
// claimant after the server-side bond disappeared. claim() still serializes
// the claimant, and a successful recovery sets sent again through complete().
func (b *configBroker) rearmAfterBondLoss() bool {
	return b != nil && b.sent.CompareAndSwap(true, false)
}

func (b *configBroker) channel() chan<- string {
	if b == nil {
		return nil
	}
	return b.ch
}

func isTURNQuotaError(errText string) bool {
	lower := strings.ToLower(errText)
	return strings.Contains(lower, "turn квота") ||
		strings.Contains(lower, "allocation quota reached") ||
		strings.Contains(lower, "error 486")
}

func isBondBindWaitTimeout(err error) bool {
	var negotiationErr bondNegotiationError
	if !errors.As(err, &negotiationErr) {
		return false
	}
	return negotiationErr.Reason == "bind wait timeout" ||
		negotiationErr.Reason == "bind wait retries exhausted"
}

func shouldRearmBondConfig(bondV2, getConf bool, sessErr error, activeWorkers int32) bool {
	if !bondV2 || getConf || sessErr == nil {
		return false
	}
	// When every active session timed out, re-elect a claimant before the
	// server's empty-bond grace expires. The bind-wait fallback also recovers
	// if cleanup won the race and token-only joins can no longer find a bond.
	return (errors.Is(sessErr, errSessionReadTimeout) && activeWorkers == 0) ||
		isBondBindWaitTimeout(sessErr)
}

func credentialsRevisionAdvanced(captured, current uint64) bool {
	return current > captured
}

// getCredsWithRevision returns a credential snapshot paired with a stable
// external-push revision. The retry is only needed when an iOS credential push
// races this read; desktop runners never advance credsRevision and therefore do
// not repeat their potentially expensive VK fetch.
func (r *Runner) getCredsWithRevision(ctx context.Context, tp *TurnParams, hash string, stats *Stats) (*Credentials, uint64, error) {
	for {
		before := r.credsRevision.Load()
		creds, err := r.getCredsWithFallback(ctx, tp, hash, stats)
		after := r.credsRevision.Load()
		if before == after {
			return creds, after, err
		}
	}
}

// quotaRetryDelay keeps quota-blocked workers alive until the TURN server has
// released old allocations. Exponential backoff avoids hammering VK, while a
// stable per-worker spread prevents all 20 workers in a room retrying together.
func quotaRetryDelay(attempt, workerID int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := quotaRetryBase
	for i := 1; i < attempt && base < quotaRetryMax; i++ {
		base *= 2
		if base > quotaRetryMax {
			base = quotaRetryMax
		}
	}
	spreadMillis := quotaRetrySpread.Milliseconds()
	seed := uint64(workerID)*1103515245 + uint64(attempt)*12345
	spread := time.Duration(seed%uint64(spreadMillis)) * time.Millisecond
	return base + spread
}

// workerGroup:
// бесшовная ротация: получить новые креды → запустить новый батч → убить старый.
func (r *Runner) workerGroup(
	ctx context.Context,
	groupID int,
	hashIndex int,
	roomID int,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	useUDP bool,
	broker *configBroker,
	workerIDs []int,
	cycleDuration time.Duration,
	pauseFlag *int32,
	deviceID, password string,
	stats *Stats,
	waitReady <-chan struct{},
	signalReady chan<- struct{},
	bondV2 bool,
	bondID bondRunnerIdentity,
) {
	// Каскадный запуск: ждем свою очередь
	if waitReady != nil {
		log.Printf("[ГРУППА #%d] Ожидание сигнала от предыдущей группы...", groupID)
		select {
		case <-waitReady:
		case <-ctx.Done():
			return
		}
	}

	cycleNumber := 0

	// Предыдущий батч
	var prevCancel context.CancelFunc
	var prevDoneChs []chan struct{}
	var commonSignalOnce sync.Once

	killBatch := func() {
		if prevCancel != nil {
			prevCancel()
			for _, ch := range prevDoneChs {
				select {
				case <-ch:
				case <-time.After(3 * time.Second):
				}
			}
			prevCancel = nil
			prevDoneChs = nil
		}
	}
	defer killBatch()

	for {
		if ctx.Err() != nil {
			return
		}

		// Doze-mode пауза: убиваем воркеров и ждём RESUME
		if atomic.LoadInt32(pauseFlag) != 0 {
			killBatch()
			log.Printf("[ГРУППА #%d] Пауза (Doze)", groupID)
			for {
				if ctx.Err() != nil {
					return
				}
				if atomic.LoadInt32(pauseFlag) == 0 {
					log.Printf("[ГРУППА #%d] Возобновление — новые креды", groupID)
					break
				}
				time.Sleep(1 * time.Second)
			}
		}

		// Получаем креды ДО убийства старого батча (бесшовная ротация)
		// Preloaded legacy single-room mode intentionally has no VKHashes list;
		// credential lookup ignores the hash in that path. Explicit multi-room
		// always validates a non-empty per-room hash list.
		hash := ""
		if len(tp.Hashes) > 0 {
			hash = tp.Hashes[hashIndex%len(tp.Hashes)]
		}
		log.Printf("[ГРУППА #%d] Цикл %d: ожидание очереди получения кредов", groupID, cycleNumber)

		r.groupAuthMutex.Lock()
		log.Printf("[ГРУППА #%d] Цикл %d: запрос кредов", groupID, cycleNumber)
		creds, credsRevision, err := r.getCredsWithRevision(ctx, tp, hash, stats)
		r.groupAuthMutex.Unlock()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[ГРУППА #%d] Ошибка кредов: %v", groupID, err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Вычисляем точное время жизни на основе ответа VK (минус 2 минуты для надёжности)
		sleepDuration := defaultCycleSecs
		if creds.Lifetime > 120 {
			sleepDuration = creds.Lifetime - 120
		}
		cycleDurationLocal := time.Duration(sleepDuration) * time.Second

		workerCount := len(workerIDs)
		if workerCount <= 0 {
			workerCount = workersPerGroup
		}
		log.Printf("[ГРУППА #%d] Запуск %d потоков (до смены кредов: %d сек)", groupID, workerCount, sleepDuration)

		log.Printf("[ГРУППА #%d] Креды OK, TURN urls=%d, %d воркеров", groupID, len(creds.TurnURLs), len(workerIDs))

		// ТЕПЕРЬ убиваем старый батч (креды уже готовы — минимальный простой)
		killBatch()

		// Создаём новый batch
		batchCtx, batchCancel := context.WithCancel(ctx)

		refreshCh := make(chan struct{}, 1)
		doneChs := make([]chan struct{}, len(workerIDs))
		var notFoundErrorWorkers sync.Map

		// Сигнализируем следующей группе, что мы успешно запустились (креды получены + 2 сек форы)
		go func() {
			commonSignalOnce.Do(func() {
				if signalReady != nil {
					time.Sleep(2000 * time.Millisecond) // Запас времени для рукопожатий (3*500ms + 500ms)
					close(signalReady)
					log.Printf("[ГРУППА #%d] Успешный старт! Передача эстафеты следующей группе...", groupID)
				}
			})
		}()

		for i, wid := range workerIDs {
			doneCh := make(chan struct{})
			doneChs[i] = doneCh

			// Stagger: 500мс между воркерами
			workerDelay := time.Duration(i) * 500 * time.Millisecond

			go func(wid int, delay time.Duration, doneCh chan struct{}, workerCreds *Credentials, workerCredsRevision uint64) {
				defer close(doneCh)

				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-batchCtx.Done():
						return
					}
				}

				// Retry loop: воркер переподключается при ошибке
				attempt := 0
				quotaAttempt := 0
				for {
					if batchCtx.Err() != nil {
						return
					}

					getConf := broker.claim()
					var cc chan<- string
					if getConf {
						cc = broker.channel()
					}

					configDelivered, sessErr := RunSession(batchCtx, tp, peer, d, localPort, useUDP,
						getConf, cc, wid, workerCreds, deviceID, password, stats, r.cfg.OnEvent,
						memoryProfileForWorkers(r.cfg.Workers, r.cfg.WorkersPerRoom > 0), bondV2, bondID, roomID)

					if getConf {
						broker.complete(configDelivered)
					}
					if shouldRearmBondConfig(bondV2, getConf, sessErr, atomic.LoadInt32(&stats.ActiveConnections)) &&
						broker.rearmAfterBondLoss() {
						log.Printf("[ВОРКЕР #%d] Bond исчез после потери сети — переизбираем config claimant", wid)
						r.eventf("warn", "bond config claimant rearmed worker=%d room=%d", wid, roomID)
					}

					if sessErr != nil {
						if batchCtx.Err() != nil {
							return
						}
						errStr := sessErr.Error()

						// Дописываем понятные пояснения для типичных ошибок со стороны балансировщиков ВК
						errStrLower := strings.ToLower(errStr)
						if strings.Contains(errStrLower, "attribute not found") ||
							strings.Contains(errStrLower, "rate limit") ||
							strings.Contains(errStrLower, "flood control") ||
							strings.Contains(errStrLower, "ip mismatch") ||
							strings.Contains(errStrLower, "error 29") {
							errStr += " (ошибка со стороны ВК)"
						}

						// Фатальные ошибки — смерть аккаунта
						if strings.Contains(errStr, "хеш мёртв") ||
							strings.Contains(errStr, "FATAL_AUTH") {
							log.Printf("[ВОРКЕР #%d] Фатальная ошибка: %s", wid, errStr)
							return
						}

						// 486 means the previous runner's allocations still occupy the
						// server quota. A worker must stay alive and retry; returning here
						// permanently stranded the pool at 8/40 in the device incident.
						if isTURNQuotaError(errStr) {
							quotaAttempt++
							delay := quotaRetryDelay(quotaAttempt, wid)
							log.Printf("[ВОРКЕР #%d] Ошибка квоты TURN; повтор через %v: %s", wid, delay, errStr)
							r.eventf("warn", "quota retry scheduled worker=%d room=%d attempt=%d delay_ms=%d", wid, roomID, quotaAttempt, delay.Milliseconds())
							select {
							case <-time.After(delay):
							case <-batchCtx.Done():
								return
							}
							currentRevision := r.credsRevision.Load()
							if credentialsRevisionAdvanced(workerCredsRevision, currentRevision) {
								r.groupAuthMutex.Lock()
								refreshed, revision, refreshErr := r.getCredsWithRevision(batchCtx, tp, hash, stats)
								r.groupAuthMutex.Unlock()
								if refreshErr != nil {
									r.eventf("warn", "quota retry credentials refresh failed worker=%d room=%d", wid, roomID)
								} else {
									workerCreds = refreshed
									workerCredsRevision = revision
									log.Printf("quota retry picked up refreshed credentials worker=%d room=%d", wid, roomID)
									r.eventf("info", "quota retry picked up refreshed credentials worker=%d room=%d", wid, roomID)
								}
							}
							continue
						}

						quotaAttempt = 0
						attempt++
						log.Printf("[ВОРКЕР #%d] Ошибка (попытка %d): %s", wid, attempt, errStr)

						// Умерли ли креды? (Строго STUN/TURN ошибки: интернет работает, но сервер отвергает ключи)
						isStunDeath := strings.Contains(errStrLower, "attribute not found") ||
							strings.Contains(errStrLower, "error 29") ||
							strings.Contains(errStrLower, "unauthorized") ||
							strings.Contains(errStrLower, "allocation mismatch") ||
							strings.Contains(errStrLower, "error 508") ||
							strings.Contains(errStrLower, "cannot create socket")

						isStreamClosed := strings.Contains(errStrLower, "stream closed")

						if isStreamClosed {
							select {
							case refreshCh <- struct{}{}:
								log.Printf("[ГРУППА #%d] Мгновенная ротация: сервер ВК закрыл поток (Stream Closed)", groupID)
							default:
							}
						} else if isStunDeath {
							notFoundErrorWorkers.Store(wid, true)
							nfCount := 0
							notFoundErrorWorkers.Range(func(k, v any) bool { nfCount++; return true })

							// Если 8 уникальных воркеров получили явный отказ от сервера — ключи 100% протухли
							if nfCount >= 8 {
								select {
								case refreshCh <- struct{}{}:
									log.Printf("[ГРУППА #%d] Досрочная ротация: сервер ВК убил сессию (у %d воркеров)", groupID, nfCount)
								default:
								}
							}
						}
					}

					if batchCtx.Err() != nil {
						return
					}

					// Пауза перед ретраем с джиттером 5-15 сек
					retryDelay := time.Duration(5+rand.Intn(11)) * time.Second
					select {
					case <-time.After(retryDelay):
					case <-batchCtx.Done():
						return
					}
				}
			}(wid, workerDelay, doneCh, creds, credsRevision)
		}

		// Сохраняем батч для бесшовной ротации
		prevCancel = batchCancel
		prevDoneChs = doneChs

		// Ждём TTL либо сигнала досрочной ротации
		select {
		case <-time.After(cycleDurationLocal):
			log.Printf("[ГРУППА #%d] TTL %v истёк, ротация", groupID, cycleDurationLocal)
		case <-refreshCh:
			log.Printf("[ГРУППА #%d] Вызвана досрочная ротация (креды не отвечали)", groupID)
		case <-ctx.Done():
			return
		}

		cycleNumber++
	}
}

// ParseHashes — парсит строку хешей
func ParseHashes(raw string) []string {
	var result []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSpace(h)
		if idx := strings.IndexAny(h, "/?#"); idx != -1 {
			h = h[:idx]
		}
		if h != "" {
			result = append(result, h)
		}
	}
	return result
}

// TurnParams — конфигурация TURN
type TurnParams struct {
	Host          string
	Port          string
	Hashes        []string
	SecondaryHash string
	Sni           string
}

// Unused import suppressor
var _ = fmt.Sprintf
