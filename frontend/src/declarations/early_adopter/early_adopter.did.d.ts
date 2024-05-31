import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';

export type ArgumentValue = { 'Int' : number } |
  { 'String' : string };
export interface CredentialSpec {
  'arguments' : [] | [Array<[string, ArgumentValue]>],
  'credential_type' : string,
}
export interface DerivationOriginData { 'origin' : string }
export type DerivationOriginError = { 'Internal' : string } |
  { 'UnsupportedOrigin' : string };
export interface DerivationOriginRequest { 'frontend_hostname' : string }
export interface EarlyAdopterResponse {
  'joined_timestamp_s' : number,
  'events' : Array<UserEventData>,
}
export interface EventData {
  'created_timestamp_s' : number,
  'code' : [] | [string],
  'event_name' : string,
}
export interface GetCredentialRequest {
  'signed_id_alias' : SignedIdAlias,
  'prepared_context' : [] | [Uint8Array | number[]],
  'credential_spec' : CredentialSpec,
}
export type HeaderField = [string, string];
export interface HttpRequest {
  'url' : string,
  'method' : string,
  'body' : Uint8Array | number[],
  'headers' : Array<HeaderField>,
  'certificate_version' : [] | [number],
}
export interface HttpResponse {
  'body' : Uint8Array | number[],
  'headers' : Array<HeaderField>,
  'status_code' : number,
}
export interface Icrc21ConsentInfo {
  'consent_message' : string,
  'language' : string,
}
export interface Icrc21ConsentPreferences { 'language' : string }
export type Icrc21Error = {
    'GenericError' : { 'description' : string, 'error_code' : bigint }
  } |
  { 'UnsupportedCanisterCall' : Icrc21ErrorInfo } |
  { 'ConsentMessageUnavailable' : Icrc21ErrorInfo };
export interface Icrc21ErrorInfo { 'description' : string }
export interface Icrc21VcConsentMessageRequest {
  'preferences' : Icrc21ConsentPreferences,
  'credential_spec' : CredentialSpec,
}
export type IssueCredentialError = { 'Internal' : string } |
  { 'SignatureNotFound' : string } |
  { 'InvalidIdAlias' : string } |
  { 'UnauthorizedSubject' : string } |
  { 'UnknownSubject' : string } |
  { 'UnsupportedCredentialSpec' : string };
export interface IssuedCredentialData { 'vc_jws' : string }
export interface IssuerConfig {
  'derivation_origin' : string,
  'idp_canister_ids' : Array<Principal>,
  'ic_root_key_der' : Uint8Array | number[],
  'frontend_hostname' : string,
}
export interface ListEventsResponse { 'events' : Array<EventData> }
export interface PrepareCredentialRequest {
  'signed_id_alias' : SignedIdAlias,
  'credential_spec' : CredentialSpec,
}
export interface PreparedCredentialData {
  'prepared_context' : [] | [Uint8Array | number[]],
}
export type RegisterError = { 'Internal' : string } |
  { 'External' : string };
export interface RegisterEventRequest { 'event_name' : string }
export interface RegisterEventResponse {
  'created_timestamp_s' : number,
  'code' : string,
  'event_name' : string,
}
export interface RegisterRequest { 'code' : string, 'event_name' : string }
export interface SignedIdAlias { 'credential_jws' : string }
export interface UserEventData {
  'joined_timestamp_s' : number,
  'event_name' : string,
}
export interface _SERVICE {
  'configure' : ActorMethod<[IssuerConfig], undefined>,
  'derivation_origin' : ActorMethod<
    [DerivationOriginRequest],
    { 'Ok' : DerivationOriginData } |
      { 'Err' : DerivationOriginError }
  >,
  'get_credential' : ActorMethod<
    [GetCredentialRequest],
    { 'Ok' : IssuedCredentialData } |
      { 'Err' : IssueCredentialError }
  >,
  'http_request' : ActorMethod<[HttpRequest], HttpResponse>,
  'list_events' : ActorMethod<[], ListEventsResponse>,
  'prepare_credential' : ActorMethod<
    [PrepareCredentialRequest],
    { 'Ok' : PreparedCredentialData } |
      { 'Err' : IssueCredentialError }
  >,
  'register_early_adopter' : ActorMethod<
    [RegisterRequest],
    { 'Ok' : EarlyAdopterResponse } |
      { 'Err' : RegisterError }
  >,
  'register_event' : ActorMethod<
    [RegisterEventRequest],
    { 'Ok' : RegisterEventResponse } |
      { 'Err' : RegisterError }
  >,
  'vc_consent_message' : ActorMethod<
    [Icrc21VcConsentMessageRequest],
    { 'Ok' : Icrc21ConsentInfo } |
      { 'Err' : Icrc21Error }
  >,
}
