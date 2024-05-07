use candid::{candid_method, CandidType, Deserialize, Principal};
use canister_sig_util::signature_map::{SignatureMap, LABEL_SIG};
use canister_sig_util::{extract_raw_root_pk_from_der, CanisterSigPublicKey, IC_ROOT_PK_DER};
use ic_cdk::api::{caller, set_certified_data, time};
use ic_cdk_macros::{init, query, update};
use ic_certification::{fork_hash, labeled_hash, pruned, Hash};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::{Bound, Storable};
use ic_stable_structures::{DefaultMemoryImpl, RestrictedMemory, StableBTreeMap, StableCell};
use include_dir::{include_dir, Dir};
use lazy_static::lazy_static;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use vc_util::issuer_api::{
    ArgumentValue, CredentialSpec, DerivationOriginData, DerivationOriginError,
    DerivationOriginRequest, GetCredentialRequest, Icrc21ConsentInfo, Icrc21Error, Icrc21ErrorInfo,
    Icrc21VcConsentMessageRequest, IssueCredentialError, IssuedCredentialData,
    PrepareCredentialRequest, PreparedCredentialData, SignedIdAlias,
};
use vc_util::{
    build_credential_jwt, did_for_principal, get_verified_id_alias_from_jws, vc_jwt_to_jws,
    vc_signing_input, vc_signing_input_hash, AliasTuple, CredentialParams,
};

use asset_util::{collect_assets, CertifiedAssets};
use ic_cdk_macros::post_upgrade;

/// We use restricted memory in order to ensure the separation between non-managed config memory (first page)
/// and the managed memory for potential other data of the canister.
type Memory = RestrictedMemory<DefaultMemoryImpl>;
type ConfigCell = StableCell<IssuerConfig, Memory>;
type EarlyAdoptersMap = StableBTreeMap<Principal, EarlyAdopterData, VirtualMemory<Memory>>;

const EARLY_ADOPTERS_MEMORY_ID: MemoryId = MemoryId::new(0u8);

const ISSUER_URL: &str = "https://internetidentity.vc";
const CREDENTIAL_URL_PREFIX: &str = "data:text/plain;charset=UTF-8,";

const MINUTE_NS: u64 = 60 * 1_000_000_000;
const PROD_II_CANISTER_ID: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
// The expiration of issued verifiable credentials.
const VC_EXPIRATION_PERIOD_NS: u64 = 15 * MINUTE_NS;
// End of year 2024 as UNIX timestamp.
const EOY_2024_TIMESTAMP_S: u32 = 1735685999;

// Type to return event data to the client
#[derive(CandidType, Clone, Deserialize)]
pub struct EventData {
    pub joined_timestamp_s: u32,
    pub event_name: String,
}

// Internal container of per-user data.
#[derive(CandidType, Clone, Deserialize)]
struct EarlyAdopterData {
    pub joined_timestamp_s: u32,
    // BTreeMap<event_name, EventRecord>
    pub events: BTreeMap<String, EventRecord>,
}
// Internal container of per-user-event data.
#[derive(CandidType, Clone, Deserialize)]
struct EventRecord {
    pub joined_timestamp_s: u32,
}

impl Storable for EarlyAdopterData {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("failed to encode EarlyAdopterData"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("failed to decode EarlyAdopterData")
    }
    const BOUND: Bound = Bound::Unbounded;
}

// User-facing container of per-user data.
#[derive(CandidType, Deserialize)]
pub struct EarlyAdopterResponse {
    pub joined_timestamp_s: u32,
    pub events: Vec<EventData>,
}

#[derive(CandidType, Deserialize)]
pub enum EarlyAdopterError {
    Internal(String),
    External(String),
}

#[derive(CandidType, Clone, Deserialize)]
pub struct RegisterRequest {
    pub event_name: Option<String>,
}

thread_local! {
    /// Stable structures
    // Static configuration of the canister set by init() or post_upgrade().
    static CONFIG: RefCell<ConfigCell> = RefCell::new(ConfigCell::init(config_memory(), IssuerConfig::default()).expect("failed to initialize stable cell"));

    static MEMORY_MANAGER: RefCell<MemoryManager<Memory>> =
        RefCell::new(MemoryManager::init(managed_memory()));

    static EARLY_ADOPTERS : RefCell<EarlyAdoptersMap> = RefCell::new(
      StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(EARLY_ADOPTERS_MEMORY_ID)),
    ));

    /// Non-stable structures
    // Canister signatures
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());
    // Assets for the management app
    static ASSETS: RefCell<CertifiedAssets> = RefCell::new(CertifiedAssets::default());



}

lazy_static! {
    // Seed and public key used for signing the credentials.
    static ref CANISTER_SIG_SEED: Vec<u8> = hash_bytes("EarlyAdopter").to_vec();
    static ref CANISTER_SIG_PK: CanisterSigPublicKey = CanisterSigPublicKey::new(ic_cdk::id(), CANISTER_SIG_SEED.clone());
}

/// Reserve the first stable memory page for the configuration stable cell.
fn config_memory() -> Memory {
    RestrictedMemory::new(DefaultMemoryImpl::default(), 0..1)
}

/// All the stable memory after the first page is managed by MemoryManager
fn managed_memory() -> Memory {
    RestrictedMemory::new(
        DefaultMemoryImpl::default(),
        1..ic_stable_structures::MAX_PAGES,
    )
}

#[cfg(target_arch = "wasm32")]
use ic_cdk::println;

#[derive(CandidType, Deserialize)]
struct IssuerConfig {
    /// Root of trust for checking canister signatures.
    ic_root_key_raw: Vec<u8>,
    /// List of canister ids that are allowed to provide id alias credentials.
    idp_canister_ids: Vec<Principal>,
    /// The derivation origin to be used by the issuer.
    derivation_origin: String,
    /// Frontend hostname to be used by the issuer.
    frontend_hostname: String,
}

impl Storable for IssuerConfig {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("failed to encode IssuerConfig"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("failed to decode IssuerConfig")
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Default for IssuerConfig {
    fn default() -> Self {
        let derivation_origin = format!("https://{}.icp0.io", ic_cdk::id().to_text());
        Self {
            ic_root_key_raw: extract_raw_root_pk_from_der(IC_ROOT_PK_DER)
                .expect("failed to extract raw root pk from der"),
            idp_canister_ids: vec![Principal::from_text(PROD_II_CANISTER_ID).unwrap()],
            derivation_origin: derivation_origin.clone(),
            frontend_hostname: derivation_origin, // by default, use DERIVATION_ORIGIN as frontend-hostname
        }
    }
}

impl From<IssuerInit> for IssuerConfig {
    fn from(init: IssuerInit) -> Self {
        Self {
            ic_root_key_raw: extract_raw_root_pk_from_der(&init.ic_root_key_der)
                .expect("failed to extract raw root pk from der"),
            idp_canister_ids: init.idp_canister_ids,
            derivation_origin: init.derivation_origin,
            frontend_hostname: init.frontend_hostname,
        }
    }
}

#[derive(CandidType, Deserialize)]
struct IssuerInit {
    /// Root of trust for checking canister signatures.
    ic_root_key_der: Vec<u8>,
    /// List of canister ids that are allowed to provide id alias credentials.
    idp_canister_ids: Vec<Principal>,
    /// The derivation origin to be used by the issuer.
    derivation_origin: String,
    /// Frontend hostname to be used by the issuer.
    frontend_hostname: String,
}

#[init]
#[candid_method(init)]
fn init(init_arg: Option<IssuerInit>) {
    if let Some(init) = init_arg {
        apply_config(init);
    };

    init_assets();
}

#[post_upgrade]
fn post_upgrade(init_arg: Option<IssuerInit>) {
    init(init_arg);
}

// TODO: restrict or remove `configure()`.
#[update]
#[candid_method]
fn configure(config: IssuerInit) {
    apply_config(config);
}

fn apply_config(init: IssuerInit) {
    CONFIG
        .with_borrow_mut(|config_cell| config_cell.set(IssuerConfig::from(init)))
        .expect("failed to apply issuer config");
}

fn authorize_vc_request(
    alias: &SignedIdAlias,
    expected_vc_subject: &Principal,
    current_time_ns: u128,
) -> Result<AliasTuple, IssueCredentialError> {
    CONFIG.with_borrow(|config| {
        let config = config.get();

        for idp_canister_id in &config.idp_canister_ids {
            if let Ok(alias_tuple) = get_verified_id_alias_from_jws(
                &alias.credential_jws,
                expected_vc_subject,
                idp_canister_id,
                &config.ic_root_key_raw,
                current_time_ns,
            ) {
                return Ok(alias_tuple);
            }
        }
        Err(IssueCredentialError::InvalidIdAlias(
            "id alias could not be verified".to_string(),
        ))
    })
}

#[update]
#[candid_method]
async fn prepare_credential(
    req: PrepareCredentialRequest,
) -> Result<PreparedCredentialData, IssueCredentialError> {
    let alias_tuple = match authorize_vc_request(&req.signed_id_alias, &caller(), time().into()) {
        Ok(alias_tuple) => alias_tuple,
        Err(err) => return Err(err),
    };

    let credential_jwt = match prepare_credential_jwt(&req.credential_spec, &alias_tuple) {
        Ok(credential) => credential,
        Err(err) => return Result::<PreparedCredentialData, IssueCredentialError>::Err(err),
    };
    let signing_input =
        vc_signing_input(&credential_jwt, &CANISTER_SIG_PK).expect("failed getting signing_input");
    let msg_hash = vc_signing_input_hash(&signing_input);

    SIGNATURES.with(|sigs| {
        let mut sigs = sigs.borrow_mut();
        sigs.add_signature(&CANISTER_SIG_SEED, msg_hash);
    });
    update_root_hash();
    Ok(PreparedCredentialData {
        prepared_context: Some(ByteBuf::from(credential_jwt.as_bytes())),
    })
}

fn update_root_hash() {
    SIGNATURES.with_borrow(|sigs| {
        ASSETS.with_borrow(|assets| {
            let prefixed_root_hash = fork_hash(
                // NB: Labels added in lexicographic order.
                &assets.root_hash(),
                &labeled_hash(LABEL_SIG, &sigs.root_hash()),
            );

            set_certified_data(&prefixed_root_hash[..]);
        })
    })
}

#[query]
#[candid_method(query)]
fn get_credential(req: GetCredentialRequest) -> Result<IssuedCredentialData, IssueCredentialError> {
    if let Err(err) = authorize_vc_request(&req.signed_id_alias, &caller(), time().into()) {
        return Result::<IssuedCredentialData, IssueCredentialError>::Err(err);
    };
    if let Err(err) = verify_early_adopter_spec_and_get_since_year(&req.credential_spec) {
        return Result::<IssuedCredentialData, IssueCredentialError>::Err(
            IssueCredentialError::UnsupportedCredentialSpec(err),
        );
    }
    let prepared_context = match req.prepared_context {
        Some(context) => context,
        None => {
            return Result::<IssuedCredentialData, IssueCredentialError>::Err(internal_error(
                "missing prepared_context",
            ))
        }
    };
    let credential_jwt = match String::from_utf8(prepared_context.into_vec()) {
        Ok(s) => s,
        Err(_) => {
            return Result::<IssuedCredentialData, IssueCredentialError>::Err(internal_error(
                "invalid prepared_context",
            ))
        }
    };
    let signing_input =
        vc_signing_input(&credential_jwt, &CANISTER_SIG_PK).expect("failed getting signing_input");
    let message_hash = vc_signing_input_hash(&signing_input);
    let sig_result = SIGNATURES.with(|sigs| {
        let sig_map = sigs.borrow();
        let certified_assets_root_hash = ASSETS.with_borrow(|assets| assets.root_hash());
        sig_map.get_signature_as_cbor(
            &CANISTER_SIG_SEED,
            message_hash,
            Some(certified_assets_root_hash),
        )
    });
    let sig = match sig_result {
        Ok(sig) => sig,
        Err(e) => {
            return Result::<IssuedCredentialData, IssueCredentialError>::Err(
                IssueCredentialError::SignatureNotFound(format!(
                    "signature not prepared or expired: {}",
                    e
                )),
            );
        }
    };
    let vc_jws =
        vc_jwt_to_jws(&credential_jwt, &CANISTER_SIG_PK, &sig).expect("failed constructing JWS");
    Result::<IssuedCredentialData, IssueCredentialError>::Ok(IssuedCredentialData { vc_jws })
}

#[update]
#[candid_method]
async fn vc_consent_message(
    req: Icrc21VcConsentMessageRequest,
) -> Result<Icrc21ConsentInfo, Icrc21Error> {
    get_vc_consent_message_en(&req.credential_spec)
}

#[update]
#[candid_method]
async fn derivation_origin(
    req: DerivationOriginRequest,
) -> Result<DerivationOriginData, DerivationOriginError> {
    get_derivation_origin(&req.frontend_hostname)
}

fn get_derivation_origin(hostname: &str) -> Result<DerivationOriginData, DerivationOriginError> {
    CONFIG.with_borrow(|config| {
        let config = config.get();
        if hostname == config.frontend_hostname {
            Ok(DerivationOriginData {
                origin: config.derivation_origin.clone(),
            })
        } else {
            Err(DerivationOriginError::UnsupportedOrigin(
                hostname.to_string(),
            ))
        }
    })
}

const EARLY_ADOPTER_VC_CONSENT_EN: &str = r###"# Verifiable Credentials Early Adopter

Credential stating that you are an Early Adopter of VC-tech since at least"###;

pub fn get_vc_consent_message_en(
    credential_spec: &CredentialSpec,
) -> Result<Icrc21ConsentInfo, Icrc21Error> {
    match verify_early_adopter_spec_and_get_since_year(credential_spec) {
        Err(err) => Err(Icrc21Error::ConsentMessageUnavailable(Icrc21ErrorInfo {
            description: err,
        })),
        Ok(since_year) => Ok(Icrc21ConsentInfo {
            consent_message: format!("{} {}.", EARLY_ADOPTER_VC_CONSENT_EN, since_year),
            language: "en".to_string(),
        }),
    }
}

// Note: not very accurate, but we cannot depend on `chrono` due to WASM-ability.
// Assumption: `year` is at least 2024 (as checked before calling this function)
fn year_to_max_timestamp_s(year: i32) -> u32 {
    const SECONDS_IN_YEAR: u32 = 31_536_000;
    EOY_2024_TIMESTAMP_S + ((year - 2024) as u32) * SECONDS_IN_YEAR
}

fn verify_early_adopter_spec_and_get_since_year(spec: &CredentialSpec) -> Result<i32, String> {
    if spec.credential_type.as_str() == "EarlyAdopter" {
        let Some(arguments) = &spec.arguments else {
            return Err("Credential spec has no arguments".to_string());
        };
        let expected_argument = "sinceYear";
        let Some(value) = arguments.get(expected_argument) else {
            return Err(format!(
                "Credential spec has no {}-argument",
                expected_argument
            ));
        };
        if arguments.len() != 1 {
            return Err("Credential spec has unexpected arguments".to_string());
        }
        let ArgumentValue::Int(year) = value else {
            return Err(format!(
                "Credential spec has unexpected value for {}-argument",
                expected_argument
            ));
        };
        if *year < 2024 {
            return Err(format!(
                "Credential spec has unsupported value for {}-argument",
                expected_argument
            ));
        };

        Ok(*year)
    } else {
        Err(format!(
            "Credential {} is not supported",
            spec.credential_type.as_str()
        ))
    }
}

#[update]
#[candid_method]
fn register_early_adopter(
    request: RegisterRequest,
) -> Result<EarlyAdopterResponse, EarlyAdopterError> {
    let user_id = caller();
    let now_s = (time() / 1_000_000_000) as u32;
    // Exit early if the event_name is present by is empty.
    if let Some(event_name) = request.clone().event_name {
        if event_name.clone().is_empty() {
            return Err(EarlyAdopterError::External(
                "event_name cannot be an empty string if present".to_string(),
            ));
        }
    }
    let current_data = EARLY_ADOPTERS.with_borrow_mut(|adopters| {
        if let Some(mut data) = adopters.get(&user_id) {
            if let Some(event_name) = request.event_name {
                let new_event = EventRecord {
                    joined_timestamp_s: now_s,
                };
                data.events.insert(event_name.clone(), new_event);
            }
            data
        } else {
            let mut events = BTreeMap::new();
            if let Some(event_name) = request.event_name {
                let first_event = EventRecord {
                    joined_timestamp_s: now_s,
                };
                events.insert(event_name.clone(), first_event);
            }
            let new_data = EarlyAdopterData {
                joined_timestamp_s: now_s,
                events,
            };
            adopters.insert(user_id, new_data.clone());
            new_data
        }
    });
    println!(
        "Registered {} at timestamp {}.",
        user_id.to_text(),
        current_data.joined_timestamp_s
    );
    let events: Vec<EventData> = current_data
        .events
        .iter()
        .map(|(event_name, data)| EventData {
            joined_timestamp_s: data.joined_timestamp_s.clone(),
            event_name: event_name.clone(),
        })
        .collect();
    Ok(EarlyAdopterResponse {
        joined_timestamp_s: current_data.joined_timestamp_s,
        events,
    })
}

#[query]
#[candid_method(query)]
pub fn http_request(req: HttpRequest) -> HttpResponse {
    // TODO: add `/metrics`-endpoint
    let parts: Vec<&str> = req.url.split('?').collect();
    let path = parts[0];
    let sigs_root_hash =
        SIGNATURES.with_borrow(|sigs| pruned(labeled_hash(LABEL_SIG, &sigs.root_hash())));
    let maybe_asset = ASSETS.with_borrow(|assets| {
        assets.get_certified_asset(path, req.certificate_version, Some(sigs_root_hash))
    });

    let mut headers = static_headers();
    match maybe_asset {
        Some(asset) => {
            headers.extend(asset.headers);
            HttpResponse {
                status_code: 200,
                body: ByteBuf::from(asset.content),
                headers,
            }
        }
        None => HttpResponse {
            status_code: 404,
            headers,
            body: ByteBuf::from(format!("Asset {} not found.", path)),
        },
    }
}

fn static_headers() -> Vec<(String, String)> {
    vec![("Access-Control-Allow-Origin".to_string(), "*".to_string())]
}

fn main() {}

fn verified_early_adopter_credential(
    subject_principal: Principal,
    credential_spec: &CredentialSpec,
) -> String {
    let params = CredentialParams {
        spec: credential_spec.clone(),
        subject_id: did_for_principal(subject_principal),
        credential_id_url: credential_id_for_principal(subject_principal),
        issuer_url: ISSUER_URL.to_string(),
        expiration_timestamp_s: exp_timestamp_s(),
    };
    build_credential_jwt(params)
}

fn exp_timestamp_s() -> u32 {
    ((time() + VC_EXPIRATION_PERIOD_NS) / 1_000_000_000) as u32
}

// Prepares a unique id for the given subject_principal.
// The returned URL has the format: "data:text/plain;charset=UTF-8,issuer:...,timestamp_ns:...,subject:..."
fn credential_id_for_principal(subject_principal: Principal) -> String {
    let issuer = format!("issuer:{}", ISSUER_URL);
    let timestamp = format!("timestamp_ns:{}", time());
    let subject = format!("subject:{}", subject_principal.to_text());
    format!(
        "{}{},{},{}",
        CREDENTIAL_URL_PREFIX, issuer, timestamp, subject
    )
}

fn prepare_credential_jwt(
    credential_spec: &CredentialSpec,
    alias_tuple: &AliasTuple,
) -> Result<String, IssueCredentialError> {
    let since_year = verify_early_adopter_spec_and_get_since_year(credential_spec)
        .map_err(IssueCredentialError::UnsupportedCredentialSpec)?;
    let max_timestamp_s = year_to_max_timestamp_s(since_year);
    EARLY_ADOPTERS.with_borrow(|adopters| {
        verify_principal_registered_and_authorized(alias_tuple.id_dapp, adopters, max_timestamp_s)
    })?;
    Ok(verified_early_adopter_credential(
        alias_tuple.id_alias,
        credential_spec,
    ))
}

fn verify_principal_registered_and_authorized(
    user: Principal,
    adopters: &EarlyAdoptersMap,
    max_timestamp_s: u32,
) -> Result<(), IssueCredentialError> {
    let Some(ea_data) = adopters.get(&user) else {
        println!(
            "*** principal {} it is not registered for early adopter credential",
            user.to_text(),
        );
        return Err(IssueCredentialError::UnauthorizedSubject(format!(
            "unregistered principal {}",
            user.to_text()
        )));
    };
    if ea_data.joined_timestamp_s < max_timestamp_s {
        Ok(())
    } else {
        println!(
            "*** {} is not authorized for EarlyAdopter credential (joined_timestamp: {}, max_timestamp: {})",
            user.to_text(), ea_data.joined_timestamp_s, max_timestamp_s
        );
        Err(IssueCredentialError::UnauthorizedSubject(format!(
            "unauthorized principal {}",
            user.to_text()
        )))
    }
}

fn internal_error(msg: &str) -> IssueCredentialError {
    IssueCredentialError::Internal(String::from(msg))
}

fn hash_bytes(value: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref());
    hasher.finalize().into()
}

// Order dependent: do not move above any function annotated with #[candid_method]!
candid::export_service!();

// Assets
static ASSET_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/frontend/dist");
pub fn init_assets() {
    ASSETS.with_borrow_mut(|assets| {
        *assets = CertifiedAssets::certify_assets(
            collect_assets(&ASSET_DIR, Some(fixup_html)),
            &static_headers(),
        );
    });

    update_root_hash()
}
pub type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    pub body: ByteBuf,
    pub certificate_version: Option<u16>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: ByteBuf,
}

fn fixup_html(html: &str) -> String {
    let canister_id = ic_cdk::api::id();

    // the string we are replacing here is part of the astro main Layout
    html.replace(
        r#"data-app"#,
        &format!(r#"data-app data-canister-id="{canister_id}""#).to_string(),
    )
}

#[cfg(test)]
mod test {
    use crate::__export_service;
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::Path;

    /// Checks candid interface type equality by making sure that the service in the did file is
    /// equal to the generated interface.
    #[test]
    fn check_candid_interface_compatibility() {
        let canister_interface = __export_service();
        service_equal(
            CandidSource::Text(&canister_interface),
            CandidSource::File(Path::new("early_adopter_issuer.did")),
        )
        .unwrap_or_else(|e| {
            panic!(
                "the canister code interface is not equal to the did file: {:?}",
                e
            )
        });
    }
}
