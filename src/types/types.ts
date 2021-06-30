export interface JwtHeader {
  alg: string ;
  typ?: string;
  kid?: string;
}

export interface JwtPayload {
  aio?: string
  aud?: string
  auth_time?: number
  azp?: string
  azpacr?: string
  client_id?: string
  event_id?: string
  exp?: number
  iat?: number
  iss?: string
  jti?: string
  name?: string
  nbf?: number
  oid?: string
  preferred_username?: string
  rh?: string
  scope?: string
  scp?: string
  sub?: string
  tid?: string
  token_use?: string
  username?: string
  uti?: string
  ver?: string
}

export interface Jwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
}
