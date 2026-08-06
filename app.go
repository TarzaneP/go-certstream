package certstream

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/google/certificate-transparency-go/loglist3"
)

const DefaultLogListUrl = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

type Certstream struct {
	logsWg          sync.WaitGroup
	loglistUrl      string
	loglistLock     sync.RWMutex
	LogList         loglist3.LogList
	websocketListen string
	webSocketServer *webSocketServer
	broadcaster     *Broadcaster
	workers         map[string]context.CancelFunc
	workersMu       sync.RWMutex
}

func NewCertstream(opts ...Option) (*Certstream, error) {
	// Default settings:
	cs := &Certstream{
		loglistUrl:      DefaultLogListUrl,
		websocketListen: ":8080",
		broadcaster:     NewBroadcaster(10000),
		workers:         make(map[string]context.CancelFunc),
	}
	// Apply options
	for _, opt := range opts {
		err := opt(cs)
		if err != nil {
			return nil, err
		}
	}
	// Configure socket server
	wsServer, err := newWebSocketServer(cs.broadcaster, cs.websocketListen)
	if err != nil {
		return nil, err
	}
	cs.webSocketServer = wsServer
	return cs, nil
}

func (cs *Certstream) updateLogList(ctx context.Context) error {
	resp, err := http.Get(cs.loglistUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var list loglist3.LogList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return err
	}

	cs.loglistLock.Lock()
	cs.LogList = list
	cs.loglistLock.Unlock()

	cs.workersMu.Lock()
	var toSpawn []struct {
		url   string
		ctLog loglist3.Log
		ctx   context.Context
	}
	validUrls := map[string]struct{}{}
	// Stop removed / expired logs
	for _, operator := range cs.LogList.Operators {
		for _, ctLog := range operator.Logs {
			if ctLog.State != nil && ctLog.State.Usable == nil {
				if cancel, ok := cs.workers[ctLog.URL]; ok {
					log.Info("Stopping worker for unusable log", "description", ctLog.Description)
					cancel()
				}
				continue
			}
			if ctLog.TemporalInterval != nil && ctLog.TemporalInterval.EndExclusive.Before(time.Now()) {
				if cancel, ok := cs.workers[ctLog.URL]; ok {
					log.Info("Stopping worker for expired log", "description", ctLog.Description)
					cancel()
				}
				continue
			}
			validUrls[ctLog.URL] = struct{}{}
			if _, exists := cs.workers[ctLog.URL]; !exists {
				log.Info("Starting worker", "description", ctLog.Description, "url", ctLog.URL)
				childCtx, cancel := context.WithCancel(ctx)
				cs.workers[ctLog.URL] = cancel
				toSpawn = append(toSpawn, struct {
					url   string
					ctLog loglist3.Log
					ctx   context.Context
				}{ctLog.URL, *ctLog, childCtx})
			}
		}
	}

	// Stop workers for URLs no longer in the loglist
	for url, cancel := range cs.workers {
		if _, exists := validUrls[url]; !exists {
			log.Info("Stopping worker for removed log", "url", url)
			cancel()
		}
	}
	cs.workersMu.Unlock()

	// Spawn outside the lock
	for _, s := range toSpawn {
		cs.logsWg.Add(1)
		go cs.spawnWorker(s.ctx, s.ctLog)
	}

	return nil
}

func (cs *Certstream) stopWorker(url string) {
	cs.workersMu.Lock()
	cancel, ok := cs.workers[url]
	if ok {
		cancel()
	}
	cs.workersMu.Unlock()
}

func (cs *Certstream) spawnWorker(parentCtx context.Context, ctLog loglist3.Log) {
	defer cs.logsWg.Done()
	defer func() {
		cs.workersMu.Lock()
		delete(cs.workers, ctLog.URL)
		cs.workersMu.Unlock()
	}()

	lw := NewLogWorker(ctLog, cs.broadcaster)
	err := lw.Run(parentCtx)
	if err != nil {
		log.Error(err)
	}
}

func (cs *Certstream) Run(ctx context.Context) error {
	if err := cs.updateLogList(ctx); err != nil {
		return err
	}

	cs.logsWg.Add(1)
	go func() {
		defer cs.logsWg.Done()
		if err := cs.webSocketServer.Run(ctx); err != nil {
			log.Error(err)
		}
	}()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cs.logsWg.Wait()
			return ctx.Err()
		case <-ticker.C:
			if err := cs.updateLogList(ctx); err != nil {
				log.Error(err)
			}
		}
	}
}
