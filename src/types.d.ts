export interface Session {
  _id: string;
  expiresAt: ExpiresAt;
  payload: Payload;
}
export interface ExpiresAt {
  $date: $date;
}
export interface $date {
  $numberLong: string;
}
export interface Payload {
  iat: number;
  exp: number;
  uid: string;
  authorizations: Authorizations;
  account: string;
  loginTs: number;
  kind: string;
  jti: string;
}
export interface Authorizations {
  client_app: ClientApp;
}
export interface ClientApp {
  sid: string;
  grantId: string;
  promptedScopes?: (string)[] | null;
  promptedClaims?: (null)[] | null;
}
