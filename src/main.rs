use std::collections::VecDeque;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_HOSTS: [&str; 2] = ["8.8.8.8", "1.1.1.1"];
const RETENTION_SECS: u64 = 24 * 60 * 60;
const LOG_RETENTION_DAYS: u64 = 30;
const ROUTE_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
const ROUTE_INTERVAL_SECS: u64 = 60 * 60;
const ROUTE_TARGET: &str = "8.8.8.8";
const HIGH_MS: f64 = 500.0;
const HIGH_DURATION_SECS: u64 = 60;
const LOSS_STREAK: usize = 5;
const DEGRADATION_GAP_SECS: u64 = 20;
const DEGRADATION_MIN_SECS: u64 = 60;
const MAX_INCIDENTS: usize = 300;
const PAGE: &str = include_str!("../web/index.html");

#[derive(Clone)]
struct Config {
    hosts: Vec<String>,
    interval: Duration,
    timeout_secs: u64,
    listen: String,
    data_dir: PathBuf,
}

#[derive(Clone)]
struct Sample {
    ts: u64,
    rtt_ms: Option<f64>,
    success: bool,
}

#[derive(Clone)]
struct Incident {
    kind: &'static str,
    started_at: u64,
    ended_at: Option<u64>,
    peak_ms: Option<f64>,
    samples: usize,
    lost_samples: usize,
}

#[derive(Clone)]
struct TraceHop {
    ttl: u8,
    address: String,
    ip: Option<String>,
    rtt_ms: Option<f64>,
}

#[derive(Clone)]
struct RouteSnapshot {
    ts: u64,
    reached: bool,
    first_external_hop: Option<TraceHop>,
    hops: Vec<TraceHop>,
    error: Option<String>,
}

struct TargetState {
    host: String,
    samples: VecDeque<Sample>,
    incidents: Vec<Incident>,
    high_run: usize,
    high_start: Option<u64>,
    high_pending_peak: Option<f64>,
    loss_run: usize,
    loss_start: Option<u64>,
    degradation_start: Option<u64>,
    degradation_last_bad: Option<u64>,
    degradation_peak_ms: Option<f64>,
    degradation_samples: usize,
    degradation_lost_samples: usize,
    degradation_had_high: bool,
    degradation_had_loss: bool,
}

impl TargetState {
    fn new(host: String) -> Self {
        Self {
            host,
            samples: VecDeque::new(),
            incidents: Vec::new(),
            high_run: 0,
            high_start: None,
            high_pending_peak: None,
            loss_run: 0,
            loss_start: None,
            degradation_start: None,
            degradation_last_bad: None,
            degradation_peak_ms: None,
            degradation_samples: 0,
            degradation_lost_samples: 0,
            degradation_had_high: false,
            degradation_had_loss: false,
        }
    }

    fn ingest(&mut self, sample: Sample) {
        let ts = sample.ts;
        let latency = sample.rtt_ms;
        let high = latency.map(|v| v >= HIGH_MS).unwrap_or(false);
        let lost = !sample.success;
        self.samples.push_back(sample);
        while self.samples.front().map(|s| ts.saturating_sub(s.ts) > RETENTION_SECS).unwrap_or(false) {
            self.samples.pop_front();
        }
        if high {
            let value = latency.unwrap_or(0.0);
            self.high_pending_peak = Some(self.high_pending_peak.map(|peak| peak.max(value)).unwrap_or(value));
        } else {
            self.high_pending_peak = None;
        }
        let pending_peak = self.high_pending_peak;
        self.advance_incident("high_latency", high, ts, pending_peak, 1, HIGH_DURATION_SECS);
        self.advance_incident("packet_loss", lost, ts, None, LOSS_STREAK, 0);
        self.advance_degradation(ts, high, lost, latency);
    }

    fn advance_incident(&mut self, kind: &'static str, bad: bool, ts: u64, latency: Option<f64>, threshold: usize, minimum_duration: u64) {
        let (run, start) = if kind == "high_latency" {
            (&mut self.high_run, &mut self.high_start)
        } else {
            (&mut self.loss_run, &mut self.loss_start)
        };
        if bad {
            if *run == 0 { *start = Some(ts); }
            *run += 1;
            if *run >= threshold {
                let already_active = self.incidents.iter().rev().any(|i| i.kind == kind && i.ended_at.is_none());
                if !already_active && ts.saturating_sub(start.unwrap_or(ts)) >= minimum_duration {
                    self.incidents.push(Incident {
                        kind,
                        started_at: start.unwrap_or(ts),
                        ended_at: None,
                        peak_ms: latency,
                        samples: *run,
                        lost_samples: if kind == "packet_loss" { *run } else { 0 },
                    });
                    if self.incidents.len() > MAX_INCIDENTS { self.incidents.remove(0); }
                } else if already_active {
                    if let Some(active) = self.incidents.iter_mut().rev().find(|i| i.kind == kind && i.ended_at.is_none()) {
                        active.samples += 1;
                        if kind == "packet_loss" { active.lost_samples += 1; }
                        if let Some(value) = latency { active.peak_ms = Some(active.peak_ms.map(|v| v.max(value)).unwrap_or(value)); }
                    }
                }
            }
        } else {
            if *run >= threshold {
                if let Some(active) = self.incidents.iter_mut().rev().find(|i| i.kind == kind && i.ended_at.is_none()) {
                    active.ended_at = Some(ts);
                }
            }
            *run = 0;
            *start = None;
        }
    }

    fn advance_degradation(&mut self, ts: u64, high: bool, lost: bool, latency: Option<f64>) {
        if self.degradation_last_bad.map(|last| ts.saturating_sub(last) > DEGRADATION_GAP_SECS).unwrap_or(false) {
            self.finish_degradation();
        }

        if high || lost {
            let start = *self.degradation_start.get_or_insert(ts);
            self.degradation_last_bad = Some(ts);
            self.degradation_samples += 1;
            self.degradation_lost_samples += usize::from(lost);
            self.degradation_had_high |= high;
            self.degradation_had_loss |= lost;
            if let Some(value) = latency {
                self.degradation_peak_ms = Some(self.degradation_peak_ms.map(|peak| peak.max(value)).unwrap_or(value));
            }

            if self.degradation_had_high && self.degradation_had_loss
                && ts.saturating_sub(start) >= DEGRADATION_MIN_SECS
            {
                if let Some(active) = self.incidents.iter_mut().rev().find(|i| i.kind == "degradation" && i.ended_at.is_none()) {
                    active.samples = self.degradation_samples;
                    active.lost_samples = self.degradation_lost_samples;
                    active.peak_ms = self.degradation_peak_ms;
                } else {
                    self.incidents.push(Incident {
                        kind: "degradation",
                        started_at: start,
                        ended_at: None,
                        peak_ms: self.degradation_peak_ms,
                        samples: self.degradation_samples,
                        lost_samples: self.degradation_lost_samples,
                    });
                    if self.incidents.len() > MAX_INCIDENTS { self.incidents.remove(0); }
                }
            }
        }
    }

    fn finish_degradation(&mut self) {
        if let (Some(start), Some(last_bad)) = (self.degradation_start, self.degradation_last_bad) {
            if let Some(active) = self.incidents.iter_mut().rev()
                .find(|i| i.kind == "degradation" && i.started_at == start && i.ended_at.is_none())
            {
                active.ended_at = Some(last_bad);
            }
        }
        self.degradation_start = None;
        self.degradation_last_bad = None;
        self.degradation_peak_ms = None;
        self.degradation_samples = 0;
        self.degradation_lost_samples = 0;
        self.degradation_had_high = false;
        self.degradation_had_loss = false;
    }

    fn snapshot_json(&self, now: u64, seconds: u64) -> String {
        let selected: Vec<&Sample> = self.samples.iter().filter(|s| now.saturating_sub(s.ts) <= seconds).collect();
        let mut out = String::with_capacity(selected.len() * 48 + 4096);
        write!(out, "{{\"host\":{},\"latest\":", json_string(&self.host)).unwrap();
        if let Some(sample) = self.samples.back() { write_sample(&mut out, sample); } else { out.push_str("null"); }
        out.push_str(",\"windows\":{");
        for (index, (name, length)) in [("5m", 300_u64), ("1h", 3600), ("24h", RETENTION_SECS)].iter().enumerate() {
            if index > 0 { out.push(','); }
            write!(out, "{}:", json_string(name)).unwrap();
            write_stats(&mut out, self.samples.iter().filter(|s| now.saturating_sub(s.ts) <= *length));
        }
        out.push_str("},\"active_incident\":");
        if let Some(incident) = self.incidents.iter().rev().find(|i| i.ended_at.is_none()) {
            write_incident(&mut out, incident, now);
        } else {
            out.push_str("null");
        }
        out.push_str(",\"incidents\":[");
        let recent = self.incidents.iter().rev().take(30).collect::<Vec<_>>();
        for (index, incident) in recent.iter().rev().enumerate() {
            if index > 0 { out.push(','); }
            write_incident(&mut out, incident, now);
        }
        out.push_str("],\"series\":[");
        let bucket_size = ((selected.len() + 999) / 1000).max(1);
        for (index, bucket) in selected.chunks(bucket_size).enumerate() {
            if index > 0 { out.push(','); }
            write_bucket(&mut out, bucket);
        }
        out.push_str("]}");
        out
    }
}

struct State {
    targets: Vec<TargetState>,
    routes: VecDeque<RouteSnapshot>,
}

impl State {
    fn new(hosts: &[String]) -> Self {
        Self { targets: hosts.iter().cloned().map(TargetState::new).collect(), routes: VecDeque::new() }
    }

    fn ingest(&mut self, host: &str, sample: Sample) {
        if let Some(target) = self.targets.iter_mut().find(|target| target.host == host) {
            target.ingest(sample);
        }
    }

    fn ingest_route(&mut self, route: RouteSnapshot) {
        self.routes.push_back(route);
        let now = unix_now();
        while self.routes.front().map(|r| now.saturating_sub(r.ts) > ROUTE_RETENTION_SECS).unwrap_or(false) {
            self.routes.pop_front();
        }
        while self.routes.len() > (ROUTE_RETENTION_SECS / ROUTE_INTERVAL_SECS) as usize + 2 {
            self.routes.pop_front();
        }
    }

    fn snapshot_json(&self, cfg: &Config, seconds: u64) -> String {
        let now = unix_now();
        let mut out = String::with_capacity(8192);
        write!(out, "{{\"generated_at\":{},\"interval_secs\":{},\"targets\":[", now, cfg.interval.as_secs()).unwrap();
        for (index, target) in self.targets.iter().enumerate() {
            if index > 0 { out.push(','); }
            out.push_str(&target.snapshot_json(now, seconds));
        }
        out.push_str("],\"route_trace\":{\"target\":");
        out.push_str(&json_string(ROUTE_TARGET));
        write!(out, ",\"interval_secs\":{},\"latest\":", ROUTE_INTERVAL_SECS).unwrap();
        if let Some(route) = self.routes.back() { write_route(&mut out, route); } else { out.push_str("null"); }
        out.push_str(",\"history\":[");
        let recent_routes = self.routes.iter().rev().take(48).collect::<Vec<_>>();
        for (index, route) in recent_routes.iter().rev().enumerate() {
            if index > 0 { out.push(','); }
            write_route(&mut out, route);
        }
        out.push_str("]}}");
        out
    }
}

fn write_sample(out: &mut String, sample: &Sample) {
    write!(out, "{{\"ts\":{},\"rtt_ms\":{},\"success\":{}}}", sample.ts, float_json(sample.rtt_ms), sample.success).unwrap();
}

fn write_hop(out: &mut String, hop: &TraceHop) {
    write!(out, "{{\"ttl\":{},\"address\":{},\"ip\":{},\"rtt_ms\":{}}}",
        hop.ttl, json_string(&hop.address),
        hop.ip.as_ref().map(|v| json_string(v)).unwrap_or_else(|| "null".to_string()),
        float_json(hop.rtt_ms)).unwrap();
}

fn write_route(out: &mut String, route: &RouteSnapshot) {
    write!(out, "{{\"ts\":{},\"reached\":{},\"first_external_hop\":", route.ts, route.reached).unwrap();
    if let Some(hop) = &route.first_external_hop { write_hop(out, hop); } else { out.push_str("null"); }
    out.push_str(",\"hops\":[");
    for (index, hop) in route.hops.iter().enumerate() {
        if index > 0 { out.push(','); }
        write_hop(out, hop);
    }
    out.push_str("],\"error\":");
    out.push_str(&route.error.as_ref().map(|v| json_string(v)).unwrap_or_else(|| "null".to_string()));
    out.push('}');
}

fn route_log_line(route: &RouteSnapshot) -> String {
    let path = route.hops.iter().map(|hop| {
        format!("{}~{}~{}~{}", hop.ttl, hop.address.replace('~', "_").replace('|', "_"),
            hop.ip.as_deref().unwrap_or(""), float_json(hop.rtt_ms))
    }).collect::<Vec<_>>().join("|");
    format!("{{\"ts\":{},\"reached\":{},\"failed\":{},\"path\":{}}}",
        route.ts, route.reached, route.error.is_some(), json_string(&path))
}

fn write_stats<'a>(out: &mut String, samples: impl Iterator<Item = &'a Sample>) {
    let mut count = 0usize;
    let mut lost = 0usize;
    let mut total = 0.0;
    let mut successes = 0usize;
    let mut max: Option<f64> = None;
    for sample in samples {
        count += 1;
        if !sample.success { lost += 1; }
        if let Some(rtt) = sample.rtt_ms {
            total += rtt;
            successes += 1;
            max = Some(max.map(|m| m.max(rtt)).unwrap_or(rtt));
        }
    }
    let loss_pct = if count == 0 { 0.0 } else { lost as f64 * 100.0 / count as f64 };
    let avg = if successes == 0 { None } else { Some(total / successes as f64) };
    write!(out, "{{\"samples\":{},\"lost\":{},\"loss_pct\":{:.2},\"avg_ms\":{},\"max_ms\":{}}}", count, lost, loss_pct, float_json(avg), float_json(max)).unwrap();
}

fn write_incident(out: &mut String, incident: &Incident, now: u64) {
    let end = incident.ended_at.unwrap_or(now);
    write!(out, "{{\"kind\":{},\"started_at\":{},\"ended_at\":{},\"duration_secs\":{},\"peak_ms\":{},\"samples\":{},\"lost_samples\":{}}}",
        json_string(incident.kind), incident.started_at,
        incident.ended_at.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        end.saturating_sub(incident.started_at), float_json(incident.peak_ms), incident.samples, incident.lost_samples).unwrap();
}

fn write_bucket(out: &mut String, samples: &[&Sample]) {
    let mut total = 0.0;
    let mut good = 0usize;
    let mut lost = 0usize;
    let mut min: Option<f64> = None;
    let mut max: Option<f64> = None;
    for sample in samples {
        if sample.success { good += 1; } else { lost += 1; }
        if let Some(value) = sample.rtt_ms {
            total += value;
            min = Some(min.map(|v| v.min(value)).unwrap_or(value));
            max = Some(max.map(|v| v.max(value)).unwrap_or(value));
        }
    }
    let avg = if good == 0 { None } else { Some(total / good as f64) };
    let loss_pct = lost as f64 * 100.0 / samples.len().max(1) as f64;
    let ts = samples.last().map(|s| s.ts).unwrap_or(0);
    write!(out, "{{\"ts\":{},\"avg_ms\":{},\"min_ms\":{},\"max_ms\":{},\"loss_pct\":{:.2}}}", ts, float_json(avg), float_json(min), float_json(max), loss_pct).unwrap();
}

fn float_json(value: Option<f64>) -> String {
    value.filter(|v| v.is_finite()).map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".to_string())
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"), '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"), c if c.is_control() => out.push(' '), c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_sample(line: &str) -> Option<(String, Sample)> {
    fn value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let marker = format!("\"{}\":", key);
        let rest = line.get(line.find(&marker)? + marker.len()..)?;
        Some(rest.split(|ch| ch == ',' || ch == '}').next()?.trim())
    }
    let host = value(line, "host").and_then(|v| v.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .map(|s| s.replace("\\\"", "\"").replace("\\\\", "\\"))
        .unwrap_or_else(|| "8.8.8.8".to_string());
    let ts = value(line, "ts")?.parse().ok()?;
    let raw_rtt = value(line, "rtt_ms")?;
    let rtt_ms = if raw_rtt == "null" { None } else { raw_rtt.parse().ok() };
    let success = value(line, "success")? == "true";
    Some((host, Sample { ts, rtt_ms, success }))
}

fn route_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{}\":", key);
    let rest = line.get(line.find(&marker)? + marker.len()..)?;
    Some(rest.split(|ch| ch == ',' || ch == '}').next()?.trim())
}

fn unquote_json(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.replace("\\\\", "\\").replace("\\\"", "\""))
}

fn parse_route_log(line: &str) -> Option<RouteSnapshot> {
    let ts = route_field(line, "ts")?.parse().ok()?;
    let reached = route_field(line, "reached")? == "true";
    let failed = route_field(line, "failed")? == "true";
    let path = unquote_json(route_field(line, "path")?).unwrap_or_default();
    let mut hops = Vec::new();
    for record in path.split('|').filter(|s| !s.is_empty()) {
        let mut fields = record.splitn(4, '~');
        let ttl = fields.next()?.parse().ok()?;
        let address = fields.next()?.to_string();
        let ip = fields.next().filter(|s| !s.is_empty()).map(str::to_string)
            .or_else(|| ip_from_address(&address));
        let raw_rtt = fields.next().unwrap_or("null");
        let rtt_ms = if raw_rtt == "null" { None } else { raw_rtt.parse().ok() };
        hops.push(TraceHop { ttl, address, ip, rtt_ms });
    }
    let first_external_hop = first_external_hop(&hops);
    Some(RouteSnapshot {
        ts,
        reached,
        first_external_hop,
        hops,
        error: if failed { Some("tracepath failed".to_string()) } else { None },
    })
}

fn ip_from_address(address: &str) -> Option<String> {
    if let Ok(ip) = address.parse::<IpAddr>() { return Some(ip.to_string()); }
    let first_label = address.split('.').next()?;
    let octets = first_label.split('-').collect::<Vec<_>>();
    if octets.len() != 4 { return None; }
    let parsed = octets.iter().map(|part| part.parse::<u8>().ok()).collect::<Option<Vec<_>>>()?;
    Some(Ipv4Addr::new(parsed[0], parsed[1], parsed[2], parsed[3]).to_string())
}

fn is_public_hop(address: &str, ip_text: Option<&str>) -> bool {
    if let Some(text) = ip_text {
        if let Ok(ip) = text.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(ip) => {
                    let [a, b, c, d] = ip.octets();
                    !(a == 0 || a == 10 || a == 127 || a >= 224
                        || (a == 100 && (64..=127).contains(&b))
                        || (a == 169 && b == 254)
                        || (a == 172 && (16..=31).contains(&b))
                        || (a == 192 && (b == 168 || (b == 0 && c == 0) || (b == 0 && c == 2)
                            || (b == 0 && c == 0 && d == 0) || (b == 0 && c == 2)
                            || (b == 88 && c == 99)))
                        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                        || (a == 203 && b == 0 && c == 113)
                        || (a == 255 && b == 255 && c == 255 && d == 255))
                }
                IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local()
                    || ip.is_unicast_link_local() || ip.is_multicast()),
            };
        }
    }
    let lower = address.to_ascii_lowercase();
    !lower.is_empty() && lower != "???" && lower != "*" && lower != "unknown" && lower != "no reply"
        && lower != "_gateway" && lower != "localhost"
        && lower != "[localhost]" && !lower.ends_with(".local")
}

fn first_external_hop(hops: &[TraceHop]) -> Option<TraceHop> {
    hops.iter().find(|hop| is_public_hop(&hop.address, hop.ip.as_deref())).cloned()
}

fn parse_trace_output(text: &str) -> RouteSnapshot {
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut reached = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let (ttl, rest) = if let Some((left, right)) = trimmed.split_once(':') {
            let ttl = match left.trim().trim_end_matches('?').parse::<u8>() { Ok(v) => v, Err(_) => continue };
            (ttl, right.trim().to_string())
        } else {
            let mut parts = trimmed.split_whitespace();
            let ttl = match parts.next().and_then(|v| v.parse::<u8>().ok()) { Some(v) => v, None => continue };
            (ttl, parts.collect::<Vec<_>>().join(" "))
        };
        let address = if rest.starts_with("no reply") {
            "no reply"
        } else { match rest.split_whitespace().next() {
            Some(v) if !v.starts_with('[') && v != "pmtu" && v != "Resume:" => v,
            _ => continue,
        }}.to_string();
        let words = rest.split_whitespace().collect::<Vec<_>>();
        let mut rtt_ms = words.iter().enumerate().find_map(|(i, word)| {
            word.strip_suffix("ms").and_then(|n| n.parse::<f64>().ok()).or_else(|| {
                if words.get(i + 1).copied() == Some("ms") { word.parse::<f64>().ok() } else { None }
            })
        });
        if address == ROUTE_TARGET || rest.contains("reached") { reached = true; }
        let ip = ip_from_address(&address);
        if let Some(existing) = hops.iter_mut().find(|hop| hop.ttl == ttl && hop.address == address) {
            if let Some(value) = rtt_ms.take() {
                existing.rtt_ms = Some(existing.rtt_ms.map(|old| old.min(value)).unwrap_or(value));
            }
        } else {
            hops.push(TraceHop { ttl, address, ip, rtt_ms });
        }
    }
    hops.sort_by_key(|hop| hop.ttl);
    let first_external_hop = first_external_hop(&hops);
    RouteSnapshot { ts: unix_now(), reached, first_external_hop, hops, error: None }
}

fn load_history(dir: &Path, hosts: &[String]) -> io::Result<State> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?.filter_map(Result::ok).map(|e| e.path())
        .filter(|p| p.file_name().and_then(|s| s.to_str()).map(|s| s.starts_with("samples-") && s.ends_with(".jsonl")).unwrap_or(false)).collect();
    files.sort();
    let mut all = Vec::new();
    for path in files {
        let file = match File::open(path) { Ok(f) => f, Err(_) => continue };
        for line in BufReader::new(file).lines().flatten() {
            if let Some(sample) = parse_sample(&line) { all.push(sample); }
        }
    }
    all.sort_by_key(|(_, sample)| sample.ts);
    let now = unix_now();
    let mut state = State::new(hosts);
    for (host, sample) in all.into_iter().filter(|(_, s)| now.saturating_sub(s.ts) <= RETENTION_SECS) {
        state.ingest(&host, sample);
    }
    state.routes = load_route_history(dir)?;
    Ok(state)
}

fn load_route_history(dir: &Path) -> io::Result<VecDeque<RouteSnapshot>> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?.filter_map(Result::ok).map(|e| e.path())
        .filter(|p| p.file_name().and_then(|s| s.to_str()).map(|s| s.starts_with("tracepath-") && s.ends_with(".jsonl")).unwrap_or(false)).collect();
    files.sort();
    let now = unix_now();
    let mut routes = VecDeque::new();
    let mut all = Vec::new();
    for path in files {
        let file = match File::open(path) { Ok(f) => f, Err(_) => continue };
        for line in BufReader::new(file).lines().flatten() {
            if let Some(route) = parse_route_log(&line) { all.push(route); }
        }
    }
    all.sort_by_key(|route| route.ts);
    for route in all.into_iter().filter(|route| now.saturating_sub(route.ts) <= ROUTE_RETENTION_SECS) {
        routes.push_back(route);
    }
    Ok(routes)
}

fn run_ping(host: &str, timeout_secs: u64) -> Sample {
    let now = unix_now();
    let timeout = timeout_secs.max(1).to_string();
    let output = Command::new("ping").env("LC_ALL", "C").args(["-n", "-c", "1", "-W", timeout.as_str(), host]).output();
    let output = match output { Ok(v) => v, Err(_) => return Sample { ts: now, rtt_ms: None, success: false } };
    let text = String::from_utf8_lossy(&output.stdout);
    let rtt_ms = text.lines().find_map(|line| {
        let start = line.find("time=")? + 5;
        let tail = &line[start..];
        let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
        tail[..end].parse::<f64>().ok()
    });
    let success = output.status.success() && rtt_ms.is_some();
    Sample { ts: now, rtt_ms: if success { rtt_ms } else { None }, success }
}

fn run_trace_command(target: &str) -> io::Result<std::process::Output> {
    match Command::new("timeout").args(["60s", "tracepath", "-m", "20", target]).output() {
        Ok(output) if output.status.code() != Some(127) => Ok(output),
        _ => match Command::new("tracepath").args(["-m", "20", target]).output() {
            Ok(output) => Ok(output),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Command::new("traceroute").args(["-n", "-q", "1", "-w", "1", "-m", "20", target]).output()
            }
            Err(error) => Err(error),
        },
    }
}

fn run_tracepath(target: &str) -> RouteSnapshot {
    let output = run_trace_command(target);
    match output {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            let mut route = parse_trace_output(&text);
            route.ts = unix_now();
            if route.hops.is_empty() {
                route.error = Some(if text.trim().is_empty() { "tracepath returned no hops".to_string() } else { text.trim().to_string() });
            }
            route
        }
        Err(error) => RouteSnapshot {
            ts: unix_now(),
            reached: false,
            first_external_hop: None,
            hops: Vec::new(),
            error: Some(format!("tracepath unavailable: {}", error)),
        },
    }
}

fn host_key(host: &str) -> String {
    host.chars().map(|ch| if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' { ch } else { '_' }).collect()
}

fn log_sample(dir: &Path, host: &str, sample: &Sample, current: &mut Option<(String, File)>) -> io::Result<()> {
    let date = date_string(sample.ts);
    if current.as_ref().map(|(d, _)| d.as_str()) != Some(date.as_str()) {
        let name = format!("samples-{}-{}.jsonl", date, host_key(host));
        let file = OpenOptions::new().create(true).append(true).open(dir.join(name))?;
        *current = Some((date, file));
        cleanup_old_logs(dir, sample.ts);
    }
    let file = &mut current.as_mut().unwrap().1;
    writeln!(file, "{{\"host\":{},\"ts\":{},\"rtt_ms\":{},\"success\":{}}}", json_string(host), sample.ts, float_json(sample.rtt_ms), sample.success)?;
    file.flush()
}

fn log_route(dir: &Path, route: &RouteSnapshot, current: &mut Option<(String, File)>) -> io::Result<()> {
    let date = date_string(route.ts);
    if current.as_ref().map(|(d, _)| d.as_str()) != Some(date.as_str()) {
        let file = OpenOptions::new().create(true).append(true).open(dir.join(format!("tracepath-{}.jsonl", date)))?;
        *current = Some((date, file));
        cleanup_old_logs(dir, route.ts);
    }
    let file = &mut current.as_mut().unwrap().1;
    writeln!(file, "{}", route_log_line(route))?;
    file.flush()
}

fn cleanup_old_logs(dir: &Path, now: u64) {
    let oldest = date_string(now.saturating_sub(LOG_RETENTION_DAYS * 86400));
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if let Some(name) = file_name.to_str() {
                let dated = name.strip_prefix("samples-").or_else(|| name.strip_prefix("tracepath-"));
                if let Some(date) = dated.and_then(|s| s.get(..10)) {
                    if date < oldest.as_str() { let _ = fs::remove_file(entry.path()); }
                }
            }
        }
    }
}

fn date_string(ts: u64) -> String {
    let z = (ts / 86400) as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

fn serve(mut stream: TcpStream, state: Arc<RwLock<State>>, cfg: Arc<Config>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.is_empty() || line == "\r\n" || line == "\n" { break; }
    }
    let (status, content_type, body) = if method != "GET" {
        ("405 Method Not Allowed", "text/plain; charset=utf-8", "GET only".to_string())
    } else if target == "/" || target.starts_with("/?") {
        ("200 OK", "text/html; charset=utf-8", PAGE.to_string())
    } else if target == "/healthz" {
        ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string())
    } else if target.starts_with("/api/state") {
        let seconds = target.split_once('?').and_then(|(_, query)| query.split('&').find_map(|p| p.strip_prefix("seconds=")?.parse::<u64>().ok())).unwrap_or(3600).clamp(60, RETENTION_SECS);
        let data = state.read().unwrap_or_else(|e| e.into_inner()).snapshot_json(&cfg, seconds);
        ("200 OK", "application/json; charset=utf-8", data)
    } else {
        ("404 Not Found", "text/plain; charset=utf-8", "not found".to_string())
    };
    write!(stream, "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{}", status, content_type, body.len(), body)?;
    stream.flush()
}

fn read_config() -> Config {
    let configured = env::var("PING_HOSTS").ok().filter(|v| !v.trim().is_empty());
    let legacy = env::var("PING_HOST").ok().filter(|v| !v.trim().is_empty());
    let raw_hosts = configured.map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>())
        .or_else(|| legacy.map(|v| vec![v.trim().to_string()]))
        .unwrap_or_else(|| DEFAULT_HOSTS.iter().map(|s| s.to_string()).collect());
    let mut hosts = Vec::new();
    for host in raw_hosts {
        if !hosts.contains(&host) { hosts.push(host); }
    }
    if hosts.is_empty() {
        hosts.extend(DEFAULT_HOSTS.iter().map(|host| host.to_string()));
    }
    let seconds = env::var("PING_INTERVAL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(1_u64).clamp(1, 60);
    let timeout = env::var("PING_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(10_u64).clamp(1, 10);
    Config {
        hosts,
        interval: Duration::from_secs(seconds),
        timeout_secs: timeout,
        listen: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8787".to_string()),
        data_dir: env::var_os("DATA_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/var/lib/pingwatch")),
    }
}

fn main() -> io::Result<()> {
    let cfg = Arc::new(read_config());
    fs::create_dir_all(&cfg.data_dir)?;
    let state = Arc::new(RwLock::new(load_history(&cfg.data_dir, &cfg.hosts)?));
    let listener = TcpListener::bind(&cfg.listen)?;

    for host in cfg.hosts.iter().cloned() {
        let worker_cfg = cfg.clone();
        let worker_state = state.clone();
        thread::Builder::new().name(format!("ping-{}", host_key(&host))).spawn(move || {
            let mut log_file = None;
            loop {
                let started = Instant::now();
                let sample = run_ping(&host, worker_cfg.timeout_secs);
                if let Err(error) = log_sample(&worker_cfg.data_dir, &host, &sample, &mut log_file) {
                    eprintln!("cannot write ping log for {}: {}", host, error);
                    log_file = None;
                }
                worker_state.write().unwrap_or_else(|e| e.into_inner()).ingest(&host, sample);
                if let Some(remaining) = worker_cfg.interval.checked_sub(started.elapsed()) { thread::sleep(remaining); }
            }
        })?;
    }

    let route_cfg = cfg.clone();
    let route_state = state.clone();
    thread::Builder::new().name("route-trace".to_string()).spawn(move || {
        let mut log_file = None;
        loop {
            let route = run_tracepath(ROUTE_TARGET);
            if let Some(error) = &route.error { eprintln!("tracepath to {}: {}", ROUTE_TARGET, error); }
            if let Err(error) = log_route(&route_cfg.data_dir, &route, &mut log_file) {
                eprintln!("cannot write tracepath log: {}", error);
                log_file = None;
            }
            route_state.write().unwrap_or_else(|e| e.into_inner()).ingest_route(route);
            thread::sleep(Duration::from_secs(ROUTE_INTERVAL_SECS));
        }
    })?;

    eprintln!("pingwatch monitoring {} target(s) every {}s plus hourly route tracing; dashboard on http://{}", cfg.hosts.len(), cfg.interval.as_secs(), cfg.listen);
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let request_state = state.clone();
                let request_cfg = cfg.clone();
                let _ = thread::Builder::new().name("http-client".to_string()).spawn(move || {
                    if let Err(error) = serve(stream, request_state, request_cfg) { eprintln!("http request error: {}", error); }
                });
            }
            Err(error) => eprintln!("http accept error: {}", error),
        }
    }
    Ok(())
}
