package analyzer

import (
	"crypto/sha1"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ErrorEvent struct {
	Fingerprint  string
	ErrorType    string
	ErrorMessage string
	RawText      string
	CreatedAt    time.Time
}

type TrendPoint struct {
	ErrorType     string
	IntervalStart time.Time
	Count         int
}

type AnalysisOptions struct {
	WindowHours int
	DeployAt    *time.Time
}

type IntelligentAnalysis struct {
	GeneratedAt        time.Time          `json:"generated_at"`
	WindowHours        int                `json:"window_hours"`
	Patterns           PatternGroups      `json:"patterns"`
	RootCauseClusters  []RootCauseCluster `json:"root_cause_clusters"`
	Trends             TrendAnalysis      `json:"trends"`
	SuggestedFixes     []SuggestedFix     `json:"suggested_fixes"`
	TotalEventsScanned int                `json:"total_events_scanned"`
}

type PatternGroups struct {
	ByStackTrace []PatternBucket `json:"by_stack_trace"`
	ByMessage    []PatternBucket `json:"by_message"`
	ByEndpoint   []PatternBucket `json:"by_endpoint"`
	ByService    []PatternBucket `json:"by_service"`
}

type PatternBucket struct {
	Key            string   `json:"key"`
	Count          int      `json:"count"`
	ErrorTypes     []string `json:"error_types"`
	Fingerprints   []string `json:"fingerprints"`
	SampleMessage  string   `json:"sample_message"`
	SampleEndpoint string   `json:"sample_endpoint,omitempty"`
	SampleService  string   `json:"sample_service,omitempty"`
}

type RootCauseCluster struct {
	ClusterID           string   `json:"cluster_id"`
	HashGroup           string   `json:"hash_group"`
	Count               int      `json:"count"`
	ErrorTypes          []string `json:"error_types"`
	Endpoints           []string `json:"endpoints"`
	Services            []string `json:"services"`
	RepresentativeError string   `json:"representative_error"`
	CosineMergedWith    []string `json:"cosine_merged_with"`
}

type TrendAnalysis struct {
	SuddenSpikes          []SpikeDetection      `json:"sudden_spikes"`
	RegressionAfterDeploy []RegressionDetection `json:"regression_after_deploy"`
}

type SpikeDetection struct {
	ErrorType        string    `json:"error_type"`
	LatestCount      int       `json:"latest_count"`
	BaselineAverage  float64   `json:"baseline_average"`
	IntervalStart    time.Time `json:"interval_start"`
	SpikeMultiplier  float64   `json:"spike_multiplier"`
	PossibleEndpoint string    `json:"possible_endpoint,omitempty"`
}

type RegressionDetection struct {
	ErrorType    string    `json:"error_type"`
	BeforeCount  int       `json:"before_count"`
	AfterCount   int       `json:"after_count"`
	DeployAt     time.Time `json:"deploy_at"`
	IncreaseRate float64   `json:"increase_rate"`
}

type SuggestedFix struct {
	Rule              string   `json:"rule"`
	Reason            string   `json:"reason"`
	Action            string   `json:"action"`
	Confidence        string   `json:"confidence"`
	RelatedErrorTypes []string `json:"related_error_types"`
}

type analysisEvent struct {
	ErrorEvent
	messageSig string
	stackSig   string
	endpoint   string
	service    string
}

var (
	numberRe     = regexp.MustCompile(`\b\d+\b`)
	hexRe        = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	multiSpaceRe = regexp.MustCompile(`\s+`)
	endpointKVRe = regexp.MustCompile(`(?i)(endpoint|path|route|url)\s*[:=]\s*([A-Z]+\s+)?(/[^\s"']+)`)
	httpVerbPath = regexp.MustCompile(`(?i)\b(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s"']+)`)
	serviceKVRe  = regexp.MustCompile(`(?i)(service|svc|component|module)\s*[:=]\s*([a-zA-Z0-9._-]+)`)
	goFrameRe    = regexp.MustCompile(`([a-zA-Z0-9_./-]+\.go:\d+)`)
	atFrameRe    = regexp.MustCompile(`\bat\s+([a-zA-Z0-9_.$/-]+\([^\)]*\))`)
)

func AnalyzeFailuresIntelligently(events []ErrorEvent, trendPoints []TrendPoint, beforeDeployCounts, afterDeployCounts map[string]int, opts AnalysisOptions) IntelligentAnalysis {
	if opts.WindowHours <= 0 {
		opts.WindowHours = 168
	}

	prepared := make([]analysisEvent, 0, len(events))
	for _, ev := range events {
		prepared = append(prepared, analysisEvent{
			ErrorEvent: ev,
			messageSig: messageSignature(ev.ErrorMessage),
			stackSig:   stackSignature(ev.RawText),
			endpoint:   extractEndpoint(ev.RawText),
			service:    extractService(ev.RawText),
		})
	}

	patterns := detectPatterns(prepared)
	clusters := detectRootCauseClusters(prepared)
	spikes := detectSpikes(trendPoints, prepared)
	regressions := detectRegression(opts.DeployAt, beforeDeployCounts, afterDeployCounts)
	fixes := suggestFixes(patterns, clusters, spikes, regressions)

	return IntelligentAnalysis{
		GeneratedAt:       time.Now().UTC(),
		WindowHours:       opts.WindowHours,
		Patterns:          patterns,
		RootCauseClusters: clusters,
		Trends: TrendAnalysis{
			SuddenSpikes:          spikes,
			RegressionAfterDeploy: regressions,
		},
		SuggestedFixes:     fixes,
		TotalEventsScanned: len(events),
	}
}

func detectPatterns(events []analysisEvent) PatternGroups {
	return PatternGroups{
		ByStackTrace: buildPatternBuckets(events, func(e analysisEvent) string {
			if e.stackSig == "" {
				return "unknown_stack"
			}
			return e.stackSig
		}),
		ByMessage: buildPatternBuckets(events, func(e analysisEvent) string {
			if e.messageSig == "" {
				return "unknown_message"
			}
			return e.messageSig
		}),
		ByEndpoint: buildPatternBuckets(events, func(e analysisEvent) string {
			if e.endpoint == "" {
				return "unknown_endpoint"
			}
			return e.endpoint
		}),
		ByService: buildPatternBuckets(events, func(e analysisEvent) string {
			if e.service == "" {
				return "unknown_service"
			}
			return e.service
		}),
	}
}

func buildPatternBuckets(events []analysisEvent, keyFn func(analysisEvent) string) []PatternBucket {
	type agg struct {
		count        int
		types        map[string]struct{}
		fingerprints map[string]struct{}
		sampleMsg    string
		sampleEP     string
		sampleSvc    string
	}
	m := make(map[string]*agg)
	for _, e := range events {
		k := keyFn(e)
		if _, ok := m[k]; !ok {
			m[k] = &agg{types: map[string]struct{}{}, fingerprints: map[string]struct{}{}, sampleMsg: e.ErrorMessage, sampleEP: e.endpoint, sampleSvc: e.service}
		}
		m[k].count++
		if e.ErrorType != "" {
			m[k].types[e.ErrorType] = struct{}{}
		}
		if e.Fingerprint != "" {
			m[k].fingerprints[e.Fingerprint] = struct{}{}
		}
	}

	out := make([]PatternBucket, 0, len(m))
	for key, a := range m {
		out = append(out, PatternBucket{
			Key:            key,
			Count:          a.count,
			ErrorTypes:     sortedKeys(a.types),
			Fingerprints:   sortedKeys(a.fingerprints),
			SampleMessage:  a.sampleMsg,
			SampleEndpoint: a.sampleEP,
			SampleService:  a.sampleSvc,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func detectRootCauseClusters(events []analysisEvent) []RootCauseCluster {
	type cluster struct {
		hashGroup  string
		count      int
		types      map[string]struct{}
		endpoints  map[string]struct{}
		services   map[string]struct{}
		sampleMsg  string
		messageSig string
	}

	groups := map[string]*cluster{}
	for _, e := range events {
		hk := hashKeyForCluster(e)
		if _, ok := groups[hk]; !ok {
			groups[hk] = &cluster{hashGroup: hk, types: map[string]struct{}{}, endpoints: map[string]struct{}{}, services: map[string]struct{}{}, sampleMsg: e.ErrorMessage, messageSig: e.messageSig}
		}
		g := groups[hk]
		g.count++
		if e.ErrorType != "" {
			g.types[e.ErrorType] = struct{}{}
		}
		if e.endpoint != "" {
			g.endpoints[e.endpoint] = struct{}{}
		}
		if e.service != "" {
			g.services[e.service] = struct{}{}
		}
	}

	mergedWith := map[string][]string{}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}

	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			a, b := groups[keys[i]], groups[keys[j]]
			if a == nil || b == nil {
				continue
			}
			score := cosineSimilarity(a.messageSig, b.messageSig)
			if score >= 0.82 {
				mergedWith[a.hashGroup] = append(mergedWith[a.hashGroup], b.hashGroup)
				mergedWith[b.hashGroup] = append(mergedWith[b.hashGroup], a.hashGroup)
			}
		}
	}

	out := make([]RootCauseCluster, 0, len(groups))
	for _, g := range groups {
		out = append(out, RootCauseCluster{
			ClusterID:           shortID(g.hashGroup),
			HashGroup:           g.hashGroup,
			Count:               g.count,
			ErrorTypes:          sortedKeys(g.types),
			Endpoints:           sortedKeys(g.endpoints),
			Services:            sortedKeys(g.services),
			RepresentativeError: g.sampleMsg,
			CosineMergedWith:    mergedWith[g.hashGroup],
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

func detectSpikes(points []TrendPoint, events []analysisEvent) []SpikeDetection {
	byType := map[string][]TrendPoint{}
	for _, p := range points {
		byType[p.ErrorType] = append(byType[p.ErrorType], p)
	}

	endpointHints := dominantEndpointByType(events)
	spikes := make([]SpikeDetection, 0)
	for typ, series := range byType {
		if len(series) < 4 {
			continue
		}
		sort.Slice(series, func(i, j int) bool { return series[i].IntervalStart.Before(series[j].IntervalStart) })
		latest := series[len(series)-1]
		prev := series[:len(series)-1]

		sum := 0
		for _, p := range prev {
			sum += p.Count
		}
		avg := float64(sum) / float64(len(prev))
		if avg < 1 {
			avg = 1
		}
		mult := float64(latest.Count) / avg
		if latest.Count >= 5 && mult >= 2.5 && (latest.Count-int(avg)) >= 3 {
			spikes = append(spikes, SpikeDetection{
				ErrorType:        typ,
				LatestCount:      latest.Count,
				BaselineAverage:  round2(avg),
				IntervalStart:    latest.IntervalStart,
				SpikeMultiplier:  round2(mult),
				PossibleEndpoint: endpointHints[typ],
			})
		}
	}

	sort.Slice(spikes, func(i, j int) bool { return spikes[i].SpikeMultiplier > spikes[j].SpikeMultiplier })
	return spikes
}

func detectRegression(deployAt *time.Time, beforeCounts, afterCounts map[string]int) []RegressionDetection {
	if deployAt == nil {
		return nil
	}

	allTypes := map[string]struct{}{}
	for t := range beforeCounts {
		allTypes[t] = struct{}{}
	}
	for t := range afterCounts {
		allTypes[t] = struct{}{}
	}

	out := make([]RegressionDetection, 0)
	for typ := range allTypes {
		before := beforeCounts[typ]
		after := afterCounts[typ]
		if after < 5 {
			continue
		}
		base := float64(before)
		if base < 1 {
			base = 1
		}
		rate := float64(after) / base
		if rate >= 1.8 && (after-before) >= 5 {
			out = append(out, RegressionDetection{
				ErrorType:    typ,
				BeforeCount:  before,
				AfterCount:   after,
				DeployAt:     deployAt.UTC(),
				IncreaseRate: round2(rate),
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IncreaseRate > out[j].IncreaseRate })
	return out
}

func suggestFixes(patterns PatternGroups, clusters []RootCauseCluster, spikes []SpikeDetection, regressions []RegressionDetection) []SuggestedFix {
	type fixKey struct{ rule, action string }
	fixMap := map[fixKey]SuggestedFix{}

	addFix := func(f SuggestedFix) {
		k := fixKey{rule: f.Rule, action: f.Action}
		if ex, ok := fixMap[k]; ok {
			ex.RelatedErrorTypes = appendUnique(ex.RelatedErrorTypes, f.RelatedErrorTypes...)
			fixMap[k] = ex
			return
		}
		f.RelatedErrorTypes = uniqueSorted(f.RelatedErrorTypes)
		fixMap[k] = f
	}

	seenTypes := map[string]struct{}{}
	for _, c := range clusters {
		for _, t := range c.ErrorTypes {
			seenTypes[t] = struct{}{}
		}
		msg := strings.ToLower(c.RepresentativeError)
		switch {
		case strings.Contains(msg, "db timeout") || strings.Contains(msg, "timeout") || hasType(c.ErrorTypes, "timeout_error"):
			addFix(SuggestedFix{
				Rule:              "DB timeout -> check connection pool",
				Reason:            "Timeout-like failures are clustered together with similar message signatures.",
				Action:            "Inspect DB pool saturation, max open connections, and upstream latency budgets.",
				Confidence:        "high",
				RelatedErrorTypes: c.ErrorTypes,
			})
		case strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset") || hasType(c.ErrorTypes, "connection_error"):
			addFix(SuggestedFix{
				Rule:              "Connection failures -> verify dependency health",
				Reason:            "Multiple events indicate unstable network or downstream service connectivity.",
				Action:            "Check service discovery, DNS, TLS settings, and retry/circuit-breaker tuning.",
				Confidence:        "medium",
				RelatedErrorTypes: c.ErrorTypes,
			})
		case strings.Contains(msg, "nil pointer") || hasType(c.ErrorTypes, "nil_pointer"):
			addFix(SuggestedFix{
				Rule:              "Nil pointer bursts -> add defensive checks",
				Reason:            "Similar stack traces imply repeated dereference of a missing object.",
				Action:            "Guard nullable values, add constructor validation, and backfill tests for absent payload fields.",
				Confidence:        "high",
				RelatedErrorTypes: c.ErrorTypes,
			})
		case strings.Contains(msg, "unauthorized") || hasType(c.ErrorTypes, "auth_error"):
			addFix(SuggestedFix{
				Rule:              "Auth errors -> verify token and clock drift",
				Reason:            "Auth-related failures are recurring in the same pattern buckets.",
				Action:            "Validate token issuer/audience, expiry skew, and API key rotation policies.",
				Confidence:        "medium",
				RelatedErrorTypes: c.ErrorTypes,
			})
		}
	}

	if len(spikes) > 0 {
		types := make([]string, 0, len(spikes))
		for _, s := range spikes {
			types = append(types, s.ErrorType)
		}
		addFix(SuggestedFix{
			Rule:              "Sudden spike -> inspect recent config/traffic shifts",
			Reason:            "One or more error types show abrupt growth over hourly baseline.",
			Action:            "Correlate spike timestamp with traffic changes, feature flags, dependency incidents, and autoscaling events.",
			Confidence:        "medium",
			RelatedErrorTypes: types,
		})
	}

	if len(regressions) > 0 {
		types := make([]string, 0, len(regressions))
		for _, r := range regressions {
			types = append(types, r.ErrorType)
		}
		addFix(SuggestedFix{
			Rule:              "500 spike after deploy -> review release delta",
			Reason:            "Error volume increased sharply after the provided deployment timestamp.",
			Action:            "Review the last deploy diff, rollback risky handlers, and compare pre/post dependency versions.",
			Confidence:        "high",
			RelatedErrorTypes: types,
		})
	}

	if len(fixMap) == 0 {
		allTypes := sortedKeys(seenTypes)
		addFix(SuggestedFix{
			Rule:              "No dominant rule hit",
			Reason:            "Patterns are distributed without a clear single failure mode.",
			Action:            "Prioritize top clusters by count and add targeted logs around endpoint/service boundaries.",
			Confidence:        "low",
			RelatedErrorTypes: allTypes,
		})
	}

	out := make([]SuggestedFix, 0, len(fixMap))
	for _, f := range fixMap {
		f.RelatedErrorTypes = uniqueSorted(f.RelatedErrorTypes)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

func dominantEndpointByType(events []analysisEvent) map[string]string {
	type key struct {
		typ string
		ep  string
	}
	counts := map[key]int{}
	best := map[string]struct {
		ep    string
		count int
	}{}
	for _, e := range events {
		if e.ErrorType == "" || e.endpoint == "" {
			continue
		}
		k := key{typ: e.ErrorType, ep: e.endpoint}
		counts[k]++
		if counts[k] > best[e.ErrorType].count {
			best[e.ErrorType] = struct {
				ep    string
				count int
			}{ep: e.endpoint, count: counts[k]}
		}
	}
	out := map[string]string{}
	for typ, b := range best {
		out[typ] = b.ep
	}
	return out
}

func hashKeyForCluster(e analysisEvent) string {
	parts := []string{e.ErrorType, e.endpoint, e.service, firstStackFrame(e.stackSig), e.messageSig}
	s := strings.Join(parts, "|")
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func messageSignature(msg string) string {
	s := strings.ToLower(strings.TrimSpace(msg))
	s = hexRe.ReplaceAllString(s, "")
	s = numberRe.ReplaceAllString(s, "")
	s = multiSpaceRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func stackSignature(raw string) string {
	frames := extractStackFrames(raw)
	if len(frames) == 0 {
		return ""
	}
	if len(frames) > 3 {
		frames = frames[:3]
	}
	for i := range frames {
		frames[i] = numberRe.ReplaceAllString(strings.ToLower(frames[i]), "")
	}
	return strings.Join(frames, " | ")
}

func extractStackFrames(raw string) []string {
	lines := strings.Split(raw, "\n")
	frames := make([]string, 0, 4)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := goFrameRe.FindStringSubmatch(line); len(m) > 1 {
			frames = append(frames, m[1])
			continue
		}
		if m := atFrameRe.FindStringSubmatch(line); len(m) > 1 {
			frames = append(frames, m[1])
		}
		if len(frames) >= 5 {
			break
		}
	}
	return frames
}

func firstStackFrame(sig string) string {
	if sig == "" {
		return ""
	}
	parts := strings.Split(sig, " | ")
	if len(parts) == 0 {
		return sig
	}
	return parts[0]
}

func extractEndpoint(raw string) string {
	if m := endpointKVRe.FindStringSubmatch(raw); len(m) > 3 {
		return strings.ToLower(strings.TrimSpace(m[3]))
	}
	if m := httpVerbPath.FindStringSubmatch(raw); len(m) > 2 {
		return strings.ToLower(strings.TrimSpace(m[2]))
	}
	return ""
}

func extractService(raw string) string {
	if m := serviceKVRe.FindStringSubmatch(raw); len(m) > 2 {
		return strings.ToLower(strings.TrimSpace(m[2]))
	}
	return ""
}

func cosineSimilarity(a, b string) float64 {
	va := vectorize(a)
	vb := vectorize(b)
	if len(va) == 0 || len(vb) == 0 {
		return 0
	}
	var dot, na, nb float64
	for k, av := range va {
		bv := vb[k]
		dot += float64(av * bv)
		na += float64(av * av)
	}
	for _, bv := range vb {
		nb += float64(bv * bv)
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func vectorize(s string) map[string]int {
	toks := strings.Fields(s)
	vec := make(map[string]int, len(toks))
	for _, t := range toks {
		if len(t) <= 2 {
			continue
		}
		vec[t]++
	}
	return vec
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func sortedKeys[K ~string](m map[K]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	for _, s := range in {
		if s != "" {
			m[s] = struct{}{}
		}
	}
	return sortedKeys(m)
}

func appendUnique(dst []string, items ...string) []string {
	seen := map[string]struct{}{}
	for _, d := range dst {
		seen[d] = struct{}{}
	}
	for _, it := range items {
		if it == "" {
			continue
		}
		if _, ok := seen[it]; ok {
			continue
		}
		dst = append(dst, it)
		seen[it] = struct{}{}
	}
	return dst
}

func hasType(types []string, target string) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

func shortID(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
