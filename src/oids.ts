import type { ShortSubjectAttributeType } from "./types.js";

export const OID = {
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extendedKeyUsage: "2.5.29.37",
  subjectAltName: "2.5.29.17",
  subjectKeyIdentifier: "2.5.29.14",
  authorityKeyIdentifier: "2.5.29.35",
  clientAuth: "1.3.6.1.5.5.7.3.2"
} as const;

export const SUBJECT_ATTRIBUTE_OIDS: Record<ShortSubjectAttributeType, string> = {
  CN: "2.5.4.3",
  O: "2.5.4.10",
  OU: "2.5.4.11",
  C: "2.5.4.6",
  ST: "2.5.4.8",
  L: "2.5.4.7",
  E: "1.2.840.113549.1.9.1",
  DC: "0.9.2342.19200300.100.1.25",
  SERIALNUMBER: "2.5.4.5",
  STREET: "2.5.4.9",
  POSTALCODE: "2.5.4.17",
  TITLE: "2.5.4.12",
  GIVENNAME: "2.5.4.42",
  SURNAME: "2.5.4.4",
  UID: "0.9.2342.19200300.100.1.1"
};
