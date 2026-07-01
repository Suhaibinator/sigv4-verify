//! `ngx_http_sigv4_verify_module`: NGINX access-phase verification of
//! S3/MinIO SigV4 presigned URLs.
//!
//! All SigV4 logic lives in the safe `sigv4-verifier` crate and all directive
//! parsing/validation in the safe `sigv4-module-config` crate. This crate is
//! only the NGINX FFI boundary: module registration, directive glue, reading
//! request structures, returning status codes, and variable plumbing.
//!
//! Panic safety: the access-phase handler wraps its Rust body in
//! `std::panic::catch_unwind` so that, in a `panic = "unwind"` build (debug and
//! test), a panic is converted to a 500 instead of unwinding into NGINX C
//! frames (which would be UB). Release builds set `panic = "abort"` (see the
//! workspace `Cargo.toml`): there `catch_unwind` cannot run its handler, so an
//! unexpected panic aborts the worker process (fail-stop) rather than
//! unwinding — still sound, but not a graceful 500. The reachable panic points
//! on the request path are guarded by the invariants noted at each call site
//! and the verifier core is fuzzed; the abort path is a backstop, not an
//! expected outcome. Note that the variable getters and pre/post-configuration
//! hooks are not individually wrapped, so any panic added to them must keep
//! this same discipline.

use std::ffi::{c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::addr_of;
use std::time::{Duration, Instant, SystemTime};

use ngx::core::{NGX_CONF_ERROR, NGX_CONF_OK, Status};
use ngx::ffi::{
    NGX_CONF_1MORE, NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET,
    NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF,
    NGX_LOG_EMERG, NGX_LOG_INFO, ngx_array_push, ngx_command_t, ngx_conf_t, ngx_http_add_variable,
    ngx_http_handler_pt, ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE,
    ngx_http_variable_t, ngx_int_t, ngx_module_t, ngx_str_t, ngx_uint_t, ngx_variable_value_t,
};
use ngx::http::{
    HTTPStatus, HttpModule, HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError,
    NgxHttpCoreModule, Request,
};
use ngx::{http_request_handler, http_variable_get, ngx_conf_log_error, ngx_log_error, ngx_string};
use sigv4_module_config::{CredentialDirective, Mode, parse_duration, parse_on_off};
use sigv4_verifier::{MAX_SIGV4_EXPIRES, Settings, Verifier};

const RESULT_ALLOW: &str = "allow";
const RESULT_DENY: &str = "deny";
const RESULT_ERROR: &str = "error";
const RESULT_OFF: &str = "off";
const RESULT_SHADOW: &str = "shadow";

const REASON_PANIC: &str = "internal_error";
const REASON_NOT_CONFIGURED: &str = "not_configured";

struct Module;

/// Module-wide (`http {}`) configuration, populated by directives and
/// compiled into a [`Verifier`] once the whole `http` block has been parsed.
#[derive(Default)]
struct MainConf {
    clock_skew: Option<Duration>,
    default_max_expires: Option<Duration>,
    supported_methods: Vec<String>,
    log_denies: Option<bool>,
    log_all: Option<bool>,
    credentials: Vec<CredentialDirective>,
    enabled_anywhere: bool,
    verifier: Option<Verifier>,
}

impl MainConf {
    fn log_denies(&self) -> bool {
        self.log_denies.unwrap_or(true)
    }

    fn log_all(&self) -> bool {
        self.log_all.unwrap_or(false)
    }
}

/// Per-location configuration: only the verification mode.
#[derive(Default)]
struct LocConf {
    mode: Mode,
}

impl Merge for LocConf {
    fn merge(&mut self, prev: &LocConf) -> Result<(), MergeConfigError> {
        self.mode = self.mode.merge(prev.mode);
        Ok(())
    }
}

/// Per-request verification outcome backing the module variables.
///
/// Owns copies of everything it exposes; it never stores pointers into
/// NGINX request memory. It is allocated from the request pool with a drop
/// cleanup, so it lives exactly as long as the request.
#[derive(Default)]
struct RequestCtx {
    result: &'static str,
    reason: &'static str,
    access_key_hash: String,
    latency_us: Option<u64>,
}

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        // SAFETY: the module struct is a static initialized before use.
        unsafe { &*addr_of!(ngx_http_sigv4_verify_module) }
    }

    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        // SAFETY: NGINX invokes preconfiguration with a valid ngx_conf_t.
        unsafe {
            for mut v in VARIABLES {
                let var = ngx_http_add_variable(cf, &mut v.name, v.flags);
                if var.is_null() {
                    return Status::NGX_ERROR.into();
                }
                (*var).get_handler = v.get_handler;
                (*var).data = v.data;
            }
        }
        Status::NGX_OK.into()
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        // SAFETY: NGINX invokes postconfiguration with a valid ngx_conf_t.
        unsafe {
            let cf = &mut *cf;
            let Some(cmcf) = NgxHttpCoreModule::main_conf_mut(cf) else {
                return Status::NGX_ERROR.into();
            };
            let h = ngx_array_push(
                &mut cmcf.phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
            ) as *mut ngx_http_handler_pt;
            if h.is_null() {
                return Status::NGX_ERROR.into();
            }
            *h = Some(sigv4_verify_access_handler);
        }
        Status::NGX_OK.into()
    }
}

unsafe impl HttpModuleMainConf for Module {
    type MainConf = MainConf;
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = LocConf;
}

static MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

static mut COMMANDS: [ngx_command_t; 8] = [
    ngx_command_t {
        name: ngx_string!("sigv4_verify"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
            as ngx_uint_t,
        set: Some(set_mode),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("sigv4_verify_clock_skew"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_clock_skew),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("sigv4_verify_default_max_expires"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_default_max_expires),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("sigv4_verify_methods"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE) as ngx_uint_t,
        set: Some(set_methods),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("sigv4_verify_log_denies"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_log_denies),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("sigv4_verify_log_all"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_log_all),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("sigv4_verify_credential"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE) as ngx_uint_t,
        set: Some(set_credential),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

// Generate the `ngx_modules` table required for a dynamic module built
// outside of the NGINX build system.
ngx::ngx_modules!(ngx_http_sigv4_verify_module);

#[used]
#[allow(non_upper_case_globals)]
pub static mut ngx_http_sigv4_verify_module: ngx_module_t = ngx_module_t {
    ctx: addr_of!(MODULE_CTX) as _,
    commands: unsafe { &COMMANDS[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

static mut VARIABLES: [ngx_http_variable_t; 4] = [
    ngx_http_variable_t {
        name: ngx_string!("sigv4_verify_result"),
        set_handler: None,
        get_handler: Some(variable_result),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("sigv4_verify_reason"),
        set_handler: None,
        get_handler: Some(variable_reason),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("sigv4_verify_access_key_hash"),
        set_handler: None,
        get_handler: Some(variable_access_key_hash),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("sigv4_verify_latency_us"),
        set_handler: None,
        get_handler: Some(variable_latency_us),
        data: 0,
        flags: 0,
        index: 0,
    },
];

// ---------------------------------------------------------------------------
// Directive glue
// ---------------------------------------------------------------------------

/// Extracts directive arguments (after the directive name) as UTF-8 strings.
///
/// # Safety
/// `cf` must be a valid `ngx_conf_t` passed to a directive handler; the
/// returned borrows must not outlive the handler invocation.
unsafe fn directive_args<'a>(cf: *mut ngx_conf_t) -> Result<Vec<&'a str>, ()> {
    // SAFETY: cf->args is a valid ngx_array_t of ngx_str_t during directive
    // parsing. Callers copy anything they keep.
    let args: &[ngx_str_t] = unsafe { (*(*cf).args).as_slice() };
    args[1..]
        .iter()
        .map(|arg| arg.to_str().map_err(|_| ()))
        .collect()
}

fn conf_error(cf: *mut ngx_conf_t, message: &str) -> *mut c_char {
    ngx_conf_log_error!(NGX_LOG_EMERG, cf, "sigv4_verify: {}", message);
    NGX_CONF_ERROR
}

/// Wraps a directive handler body so panics report a config error instead of
/// unwinding into NGINX.
fn guard_conf(cf: *mut ngx_conf_t, body: impl FnOnce() -> *mut c_char) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(rc) => rc,
        Err(_) => conf_error(cf, "panic while parsing configuration"),
    }
}

extern "C" fn set_mode(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    guard_conf(cf, || {
        // SAFETY: conf points at this module's LocConf for the current block.
        let loc = unsafe { &mut *(conf as *mut LocConf) };
        if loc.mode != Mode::Unset {
            return c"is duplicate".as_ptr() as *mut c_char;
        }
        let Ok(args) = (unsafe { directive_args(cf) }) else {
            return conf_error(cf, "directive arguments must be valid UTF-8");
        };
        match Mode::parse(args[0]) {
            Ok(mode) => {
                loc.mode = mode;
                if mode.verifies() {
                    // SAFETY: cf is valid and the http main conf exists while
                    // parsing directives inside the http block.
                    if let Some(main) = Module::main_conf_mut(unsafe { &*cf }) {
                        main.enabled_anywhere = true;
                    }
                }
                NGX_CONF_OK
            }
            Err(err) => conf_error(cf, &err.to_string()),
        }
    })
}

fn set_main_duration(
    cf: *mut ngx_conf_t,
    conf: *mut c_void,
    field: impl FnOnce(&mut MainConf) -> &mut Option<Duration>,
) -> *mut c_char {
    guard_conf(cf, || {
        // SAFETY: conf points at this module's MainConf.
        let main = unsafe { &mut *(conf as *mut MainConf) };
        let slot = field(main);
        if slot.is_some() {
            return c"is duplicate".as_ptr() as *mut c_char;
        }
        let Ok(args) = (unsafe { directive_args(cf) }) else {
            return conf_error(cf, "directive arguments must be valid UTF-8");
        };
        match parse_duration(args[0]) {
            Ok(duration) => {
                *slot = Some(duration);
                NGX_CONF_OK
            }
            Err(err) => conf_error(cf, &err.to_string()),
        }
    })
}

extern "C" fn set_clock_skew(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    set_main_duration(cf, conf, |main| &mut main.clock_skew)
}

extern "C" fn set_default_max_expires(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    set_main_duration(cf, conf, |main| &mut main.default_max_expires)
}

extern "C" fn set_methods(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    guard_conf(cf, || {
        // SAFETY: conf points at this module's MainConf.
        let main = unsafe { &mut *(conf as *mut MainConf) };
        if !main.supported_methods.is_empty() {
            return c"is duplicate".as_ptr() as *mut c_char;
        }
        let Ok(args) = (unsafe { directive_args(cf) }) else {
            return conf_error(cf, "directive arguments must be valid UTF-8");
        };
        for method in &args {
            if !matches!(*method, "GET" | "HEAD") {
                return conf_error(cf, &format!("unsupported method {method:?}"));
            }
        }
        main.supported_methods = args.iter().map(|s| s.to_string()).collect();
        NGX_CONF_OK
    })
}

fn set_main_flag(
    cf: *mut ngx_conf_t,
    conf: *mut c_void,
    field: impl FnOnce(&mut MainConf) -> &mut Option<bool>,
) -> *mut c_char {
    guard_conf(cf, || {
        // SAFETY: conf points at this module's MainConf.
        let main = unsafe { &mut *(conf as *mut MainConf) };
        let slot = field(main);
        if slot.is_some() {
            return c"is duplicate".as_ptr() as *mut c_char;
        }
        let Ok(args) = (unsafe { directive_args(cf) }) else {
            return conf_error(cf, "directive arguments must be valid UTF-8");
        };
        match parse_on_off(args[0]) {
            Ok(value) => {
                *slot = Some(value);
                NGX_CONF_OK
            }
            Err(err) => conf_error(cf, &err.to_string()),
        }
    })
}

extern "C" fn set_log_denies(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    set_main_flag(cf, conf, |main| &mut main.log_denies)
}

extern "C" fn set_log_all(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    set_main_flag(cf, conf, |main| &mut main.log_all)
}

extern "C" fn set_credential(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    guard_conf(cf, || {
        // SAFETY: conf points at this module's MainConf.
        let main = unsafe { &mut *(conf as *mut MainConf) };
        let Ok(args) = (unsafe { directive_args(cf) }) else {
            return conf_error(cf, "directive arguments must be valid UTF-8");
        };
        match CredentialDirective::parse(&args) {
            Ok(directive) => {
                if main
                    .credentials
                    .iter()
                    .any(|existing| existing.access_key == directive.access_key)
                {
                    return conf_error(
                        cf,
                        &format!("duplicate access key {:?}", directive.access_key),
                    );
                }
                main.credentials.push(directive);
                NGX_CONF_OK
            }
            Err(err) => conf_error(cf, &err.to_string()),
        }
    })
}

/// Compiles the final verifier after the whole `http {}` block is parsed.
/// Any validation failure here fails `nginx -t` and reload.
extern "C" fn init_main_conf(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char {
    guard_conf(cf, || {
        // SAFETY: conf points at this module's MainConf, fully populated.
        let main = unsafe { &mut *(conf as *mut MainConf) };

        if main.credentials.is_empty() {
            if main.enabled_anywhere {
                return conf_error(
                    cf,
                    "sigv4_verify is enabled but no sigv4_verify_credential is configured",
                );
            }
            // Module loaded but unused: nothing to compile.
            return NGX_CONF_OK;
        }

        if let Some(max_expires) = main.default_max_expires
            && (max_expires.is_zero() || max_expires > MAX_SIGV4_EXPIRES)
        {
            return conf_error(
                cf,
                "sigv4_verify_default_max_expires must be between 1s and 7d",
            );
        }

        let mut credentials = Vec::with_capacity(main.credentials.len());
        for directive in &main.credentials {
            match directive.resolve() {
                Ok(credential) => credentials.push(credential),
                Err(err) => return conf_error(cf, &err.to_string()),
            }
        }

        let mut settings = Settings::default();
        if let Some(clock_skew) = main.clock_skew {
            settings.allowed_clock_skew = clock_skew;
        }
        if let Some(default_max_expires) = main.default_max_expires {
            settings.default_max_expires = default_max_expires;
        }
        if !main.supported_methods.is_empty() {
            settings.supported_methods = main.supported_methods.clone();
        }

        match Verifier::new(settings, credentials) {
            Ok(verifier) => {
                main.verifier = Some(verifier);
                NGX_CONF_OK
            }
            Err(err) => conf_error(cf, &err.to_string()),
        }
    })
}

// ---------------------------------------------------------------------------
// Access-phase handler
// ---------------------------------------------------------------------------

http_request_handler!(sigv4_verify_access_handler, |request: &mut Request| {
    match catch_unwind(AssertUnwindSafe(|| handle_request(request))) {
        Ok(status) => status,
        Err(_) => {
            // The panic payload is intentionally not logged: it could contain
            // request or key material. The stable reason string is enough.
            if let Some(ctx) = alloc_ctx(request) {
                ctx.result = RESULT_ERROR;
                ctx.reason = REASON_PANIC;
            }
            HTTPStatus::INTERNAL_SERVER_ERROR.into()
        }
    }
});

/// Allocates the per-request context from the request pool and registers it
/// as this module's request ctx.
fn alloc_ctx(request: &mut Request) -> Option<&'static mut RequestCtx> {
    let ctx = request.pool().allocate::<RequestCtx>(RequestCtx::default());
    if ctx.is_null() {
        return None;
    }
    request.set_module_ctx(ctx as *mut c_void, Module::module());
    // SAFETY: pool allocation succeeded; the pool cleanup drops the value
    // when the request pool is destroyed, and variable handlers only run
    // while the request (and its pool) is alive.
    Some(unsafe { &mut *ctx })
}

fn handle_request(request: &mut Request) -> Status {
    // NGINX always initializes the location conf for a loaded module, so a
    // missing one indicates an internal inconsistency. Fail closed (500) rather
    // than defaulting to `Unset`, which would pass the request through
    // unverified — the one asymmetry where an unexpected internal state would
    // otherwise open instead of close.
    let Some(loc) = Module::location_conf(request) else {
        return HTTPStatus::INTERNAL_SERVER_ERROR.into();
    };
    let mode = loc.mode;

    let Some(ctx) = alloc_ctx(request) else {
        return HTTPStatus::INTERNAL_SERVER_ERROR.into();
    };

    if !mode.verifies() {
        ctx.result = RESULT_OFF;
        return Status::NGX_DECLINED;
    }

    // init_main_conf rejects enabled configs without credentials, so a missing
    // main conf or verifier is unreachable in a loaded config; fail closed
    // regardless. Bind `main` once and read the verifier from it (no second
    // lookup, no `expect` panic point on the request path).
    let (main, verifier) = match Module::main_conf(request) {
        Some(main) => match main.verifier.as_ref() {
            Some(verifier) => (main, verifier),
            None => {
                ctx.result = RESULT_ERROR;
                ctx.reason = REASON_NOT_CONFIGURED;
                return HTTPStatus::INTERNAL_SERVER_ERROR.into();
            }
        },
        None => {
            ctx.result = RESULT_ERROR;
            ctx.reason = REASON_NOT_CONFIGURED;
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    let started = Instant::now();

    let r = request.as_ref();
    // SAFETY: method_name and unparsed_uri are request-pool ngx_str_t values
    // valid for the duration of this handler; headers_in.host is either null
    // or a valid header entry. The borrowed slices do not outlive this call.
    let (method, raw_uri, host) = unsafe {
        let method = r.method_name.as_bytes();
        let raw_uri = r.unparsed_uri.as_bytes();
        let host = match r.headers_in.host.as_ref() {
            Some(host) => host.value.as_bytes(),
            None => &[],
        };
        (method, raw_uri, host)
    };

    // A non-UTF-8 method or host is outside the supported envelope; the
    // empty string makes the verifier deny with `missing_metadata`.
    let method = std::str::from_utf8(method).unwrap_or("");
    let host = std::str::from_utf8(host).unwrap_or("");

    let outcome = verifier.verify(method, raw_uri, host, SystemTime::now());
    let latency_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

    ctx.reason = outcome.reason;
    ctx.access_key_hash = outcome.access_key_hash.clone();
    ctx.latency_us = Some(latency_us);
    ctx.result = match (outcome.allowed, mode) {
        (_, Mode::Shadow) => RESULT_SHADOW,
        (true, _) => RESULT_ALLOW,
        (false, _) => RESULT_DENY,
    };

    if main.log_all() || (!outcome.allowed && main.log_denies()) {
        let path = String::from_utf8_lossy(&outcome.path);
        // The raw query is never logged: it contains the signature.
        ngx_log_error!(
            NGX_LOG_INFO,
            request.log(),
            "sigv4_verify: result={} reason={} access_key_hash={} method={} host={} path={}",
            ctx.result,
            ctx.reason,
            if ctx.access_key_hash.is_empty() {
                "-"
            } else {
                &ctx.access_key_hash
            },
            method,
            host,
            path,
        );
    }

    match (outcome.allowed, mode) {
        (true, _) => Status::NGX_OK,
        (false, Mode::Shadow) => Status::NGX_OK,
        (false, _) => HTTPStatus::FORBIDDEN.into(),
    }
}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

/// Binds `bytes` to a variable value.
///
/// # Safety
/// `v` must be a valid variable value pointer and `bytes` must stay valid for
/// the rest of the request (request-ctx fields, request-pool allocations, and
/// statics all qualify).
unsafe fn bind_variable(v: *mut ngx_variable_value_t, bytes: &[u8]) {
    unsafe {
        (*v).set_valid(1);
        (*v).set_no_cacheable(0);
        (*v).set_not_found(0);
        (*v).set_len(bytes.len() as u32);
        (*v).data = bytes.as_ptr() as *mut u8;
    }
}

fn request_ctx(request: &Request) -> Option<&RequestCtx> {
    request.get_module_ctx::<RequestCtx>(Module::module())
}

http_variable_get!(
    variable_result,
    |request: &mut Request, v: *mut ngx_variable_value_t, _: usize| {
        match request_ctx(request).map(|ctx| ctx.result) {
            Some(result) if !result.is_empty() => {
                // SAFETY: v is valid; result is a &'static str.
                unsafe { bind_variable(v, result.as_bytes()) };
            }
            // SAFETY: v is a valid variable value pointer.
            _ => unsafe { (*v).set_not_found(1) },
        }
        Status::NGX_OK
    }
);

http_variable_get!(
    variable_reason,
    |request: &mut Request, v: *mut ngx_variable_value_t, _: usize| {
        match request_ctx(request).map(|ctx| ctx.reason) {
            Some(reason) if !reason.is_empty() => {
                // SAFETY: v is valid; reason is a &'static str.
                unsafe { bind_variable(v, reason.as_bytes()) };
            }
            // SAFETY: v is a valid variable value pointer.
            _ => unsafe { (*v).set_not_found(1) },
        }
        Status::NGX_OK
    }
);

http_variable_get!(
    variable_access_key_hash,
    |request: &mut Request, v: *mut ngx_variable_value_t, _: usize| {
        match request_ctx(request) {
            Some(ctx) if !ctx.access_key_hash.is_empty() => {
                // SAFETY: v is valid; the hash string is owned by the request
                // ctx, which lives until the request pool is destroyed after
                // logging completes.
                unsafe { bind_variable(v, ctx.access_key_hash.as_bytes()) };
            }
            // SAFETY: v is a valid variable value pointer.
            _ => unsafe { (*v).set_not_found(1) },
        }
        Status::NGX_OK
    }
);

http_variable_get!(
    variable_latency_us,
    |request: &mut Request, v: *mut ngx_variable_value_t, _: usize| {
        match request_ctx(request).and_then(|ctx| ctx.latency_us) {
            Some(latency_us) => {
                let text = latency_us.to_string();
                let pool = request.pool();
                let data = pool.alloc_unaligned(text.len()) as *mut u8;
                if data.is_null() {
                    return Status::NGX_ERROR;
                }
                // SAFETY: data is a fresh request-pool allocation of
                // text.len() bytes; v is valid and the copied bytes live in
                // the request pool.
                unsafe {
                    std::ptr::copy_nonoverlapping(text.as_ptr(), data, text.len());
                    bind_variable(v, std::slice::from_raw_parts(data, text.len()));
                }
            }
            // SAFETY: v is a valid variable value pointer.
            None => unsafe { (*v).set_not_found(1) },
        }
        Status::NGX_OK
    }
);
