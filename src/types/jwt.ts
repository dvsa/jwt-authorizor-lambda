export interface JwtHeader {
  alg: string ;
  typ?: string;
  kid?: string;
}

export interface JwtPayload {
  aud?: string
  exp: number
  iss: string
  [index: string]: string | number;
}

export interface Jwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
}
