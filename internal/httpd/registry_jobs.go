package httpd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// A pull from another registry or a push to one takes as long as its layers
// take to cross the network, which for a large image is minutes, and so does
// a file the listing fetches from a URL, or an image archive that is read. So
// the page does not wait for it: the server runs it as a job, and the page
// asks how far it has got until it is over. A job lives in memory only,
// belongs to the account that started it, and is forgotten an hour after it
// ended. The credentials it was given are in the closure it runs and nowhere
// else.

const (
	jobPull   = "pull"
	jobPush   = "push"
	jobFetch  = "fetch"
	jobImport = "import"

	jobRunning = "running"
	// jobReady is an import that has read its archive and waits to be told
	// what to store of it
	jobReady     = "ready"
	jobDone      = "done"
	jobFailed    = "failed"
	jobCancelled = "cancelled"
)

// maxRunningJobs is how many transfers may run at once, for everyone
// together: each holds connections and a share of the bandwidth.
const maxRunningJobs = 4

// jobRetention is how long a job that ended is kept for the page to read.
const jobRetention = time.Hour

var errTooManyJobs = errors.New("too many transfers are running; wait for one to finish")

// errStalled is a transfer that went remoteIdleTimeout without moving a byte.
var errStalled = errors.New("the transfer stalled: nothing arrived for too long")

// registryJob is one pull or push.
type registryJob struct {
	id    string
	kind  string
	owner string
	// what says what is copied where, for the page and the log.
	what    string
	started time.Time
	cancel  context.CancelFunc

	blobsTotal, blobsDone atomic.Int64
	bytesTotal, bytesDone atomic.Int64

	mu       sync.Mutex
	state    string
	message  string
	finished time.Time
	// phase is the step of an import the job is at.
	phase string
	// offer is what an import found in its archive, once it is ready, and
	// choice is where the page's answer to it comes. confirmed says an
	// answer was given, since only one is taken.
	offer     []importImageJSON
	choice    chan importChoice
	confirmed bool
}

// registryJobJSON is what the page reads of a job.
type registryJobJSON struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	What       string `json:"what"`
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	BlobsTotal int64  `json:"blobsTotal"`
	BlobsDone  int64  `json:"blobsDone"`
	BytesTotal int64  `json:"bytesTotal"`
	BytesDone  int64  `json:"bytesDone"`
	Started    string `json:"started"`
	Finished   string `json:"finished,omitempty"`
	// Phase and Images are an import's: the step it is at, and what it
	// found in its archive.
	Phase  string            `json:"phase,omitempty"`
	Images []importImageJSON `json:"images,omitempty"`
}

func (j *registryJob) view() registryJobJSON {
	j.mu.Lock()
	defer j.mu.Unlock()
	view := registryJobJSON{ID: j.id, Kind: j.kind, What: j.what, State: j.state, Message: j.message,
		BlobsTotal: j.blobsTotal.Load(), BlobsDone: j.blobsDone.Load(),
		BytesTotal: j.bytesTotal.Load(), BytesDone: j.bytesDone.Load(),
		Started: j.started.UTC().Format(time.RFC3339), Phase: j.phase}
	if j.state == jobReady {
		view.Images = j.offer
	}
	if !j.finished.IsZero() {
		view.Finished = j.finished.UTC().Format(time.RFC3339)
	}
	return view
}

func (j *registryJob) running() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state == jobRunning || j.state == jobReady
}

func (j *registryJob) end(state, message string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.state, j.message, j.finished = state, message, time.Now()
}

// setPhase moves an import on to its next step, which starts counting anew.
func (j *registryJob) setPhase(phase string, bytes int64) {
	j.mu.Lock()
	j.phase = phase
	j.mu.Unlock()
	j.blobsTotal.Store(0)
	j.blobsDone.Store(0)
	j.bytesTotal.Store(bytes)
	j.bytesDone.Store(0)
}

// ready offers what an import found, for the page to choose from.
func (j *registryJob) ready(offer []importImageJSON) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.state, j.offer = jobReady, offer
	if j.choice == nil {
		j.choice = make(chan importChoice, 1)
	}
}

// choose hands the page's answer to an import that is ready for it. Only the
// first answer is taken.
func (j *registryJob) choose(choice importChoice) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != jobReady || j.confirmed {
		return false
	}
	// running again from now on, so the page that sent the answer never
	// reads the job as still waiting for one
	j.confirmed = true
	j.state, j.offer = jobRunning, nil
	j.choice <- choice
	return true
}

// await waits for the page's answer to what an import offered, until the
// job is stopped or timeout passes.
func (j *registryJob) await(ctx context.Context, timeout time.Duration) (importChoice, error) {
	j.mu.Lock()
	choice := j.choice
	j.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case chosen := <-choice:
		return chosen, nil
	case <-ctx.Done():
		return importChoice{}, ctx.Err()
	case <-timer.C:
		return importChoice{}, errImportUnanswered
	}
}

// plan sets what the job has to move, once it knows.
func (j *registryJob) plan(blobs int, size int64) {
	j.blobsTotal.Store(int64(blobs))
	j.bytesTotal.Store(size)
}

// skipped counts a blob that did not have to be moved as moved.
func (j *registryJob) skipped(size int64) {
	j.bytesDone.Add(size)
	j.blobsDone.Add(1)
}

// registryJobs are the jobs of a server.
type registryJobs struct {
	mu   sync.Mutex
	jobs map[string]*registryJob
}

// start runs a job. run returns what the job says when it succeeds.
func (s *Server) startJob(kind, owner, what string, run func(ctx context.Context, job *registryJob) (string, error)) (*registryJob, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &registryJob{id: hex.EncodeToString(raw), kind: kind, owner: owner, what: what,
		started: time.Now(), cancel: cancel, state: jobRunning}

	jobs := &s.registryJobs
	jobs.mu.Lock()
	running := 0
	for id, other := range jobs.jobs {
		if other.running() {
			running++
			continue
		}
		other.mu.Lock()
		old := time.Since(other.finished) > jobRetention
		other.mu.Unlock()
		if old {
			delete(jobs.jobs, id)
		}
	}
	if running >= maxRunningJobs {
		jobs.mu.Unlock()
		cancel()
		return nil, errTooManyJobs
	}
	if jobs.jobs == nil {
		jobs.jobs = map[string]*registryJob{}
	}
	jobs.jobs[job.id] = job
	// the shutdown waits for the job, which it stops first
	s.wg.Add(1)
	jobs.mu.Unlock()

	go func() {
		defer s.wg.Done()
		defer cancel()
		go func() {
			select {
			case <-s.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		message, err := run(ctx, job)
		switch {
		case err == nil:
			job.end(jobDone, message)
		case ctx.Err() != nil:
			// stopped from the page, or by the shutdown: whatever the transfer
			// failed with then is only that
			job.end(jobCancelled, "Stopped.")
		default:
			job.end(jobFailed, err.Error())
		}
	}()
	return job, nil
}

// job finds a job of an account. Someone else's is not there to it.
func (s *Server) job(id, owner string) *registryJob {
	jobs := &s.registryJobs
	jobs.mu.Lock()
	defer jobs.mu.Unlock()
	job := jobs.jobs[id]
	if job == nil || job.owner != owner {
		return nil
	}
	return job
}

// progressReader counts what passes through it towards a job, and gives up
// when nothing has passed for remoteIdleTimeout: a connection that stalls
// without closing would otherwise hold the job forever.
type progressReader struct {
	r     io.Reader
	job   *registryJob
	timer *time.Timer
}

// watch wraps a reader of a transfer. cancel is what stops the transfer when
// it goes idle, with errStalled as the cause; the caller stops the timer with
// done once it is over.
func watch(r io.Reader, job *registryJob, cancel context.CancelCauseFunc) *progressReader {
	return &progressReader{r: r, job: job,
		timer: time.AfterFunc(remoteIdleTimeout, func() { cancel(errStalled) })}
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.job.bytesDone.Add(int64(n))
		p.timer.Reset(remoteIdleTimeout)
	}
	return n, err
}

func (p *progressReader) done() {
	p.timer.Stop()
}
