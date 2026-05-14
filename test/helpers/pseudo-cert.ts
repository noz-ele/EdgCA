// Construct a structurally-valid v3 X.509 cert DER that carries the given
// SPKI but is not signed by anything that verifies — sufficient to exercise
// exportPkcs12's SPKI extraction with non-EC key material. NOT a real cert
// and must not be used for anything other than testing the byte-level
// PKCS#12 build path.

import {
  bitString,
  explicit,
  integer,
  nullValue,
  oid,
  printableString,
  sequence,
  set,
  utcTime
} from "../../src/der.js";
import { encodePem } from "../../src/pem.js";

const SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const COMMON_NAME = "2.5.4.3";

export function buildPseudoV3CertWithSpki(spkiDer: Uint8Array): Uint8Array {
  const sigAlgId = sequence(oid(SHA256_WITH_RSA), nullValue());
  const name = (cn: string) =>
    sequence(set(sequence(oid(COMMON_NAME), printableString(cn))));
  const validity = sequence(
    utcTime(new Date("2026-01-01T00:00:00Z")),
    utcTime(new Date("2030-01-01T00:00:00Z"))
  );
  const tbs = sequence(
    explicit(0, integer(2n)),
    integer(1n),
    sigAlgId,
    name("test-issuer"),
    validity,
    name("test-subject"),
    spkiDer
  );
  const signatureValue = bitString(new Uint8Array(256));
  return sequence(tbs, sigAlgId, signatureValue);
}

export function pseudoV3CertPemWithSpki(spkiDer: Uint8Array): string {
  return encodePem("CERTIFICATE", buildPseudoV3CertWithSpki(spkiDer));
}
