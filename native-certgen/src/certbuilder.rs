use crate::error::{CertGenError, Result};
use crate::keybox::ParsedKeybox;
use crate::types::{CertGenParams, GeneratedKeyPair};

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use time::OffsetDateTime;

const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

pub fn build_certificate_chain(
    key_pair: &GeneratedKeyPair,
    attestation_ext_der: &[u8],
    keybox: &ParsedKeybox,
    params: &CertGenParams,
) -> Result<Vec<Vec<u8>>> {
    let issuer_key = KeyPair::try_from(keybox.signing_key_der.as_slice())
        .map_err(|e| CertGenError::CertBuildFailed(format!("keybox key parse: {e}")))?;

    let issuer_cert = build_issuer_cert(&issuer_key, &keybox.issuer_dn_der)?;

    let subject_key = KeyPair::try_from(key_pair.private_key_pkcs8.as_slice())
        .map_err(|e| CertGenError::CertBuildFailed(format!("subject key parse: {e}")))?;

    let leaf_params = build_leaf_params(attestation_ext_der, keybox, params)?;

    let leaf_cert = leaf_params
        .signed_by(&subject_key, &issuer_cert, &issuer_key)
        .map_err(|e| CertGenError::CertBuildFailed(format!("signing: {e}")))?;

    let mut chain = Vec::with_capacity(1 + keybox.cert_chain_ders.len());
    chain.push(leaf_cert.der().to_vec());
    for cert_der in &keybox.cert_chain_ders {
        chain.push(cert_der.clone());
    }

    Ok(chain)
}

fn build_issuer_cert(
    issuer_key: &KeyPair,
    issuer_dn_der: &[u8],
) -> Result<rcgen::Certificate> {
    let mut issuer_params = CertificateParams::default();
    issuer_params.distinguished_name = parse_dn_from_der(issuer_dn_der)?;
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // Suppress AKI/SKI generation — we only need this cert as a signing vehicle
    issuer_params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![]);

    issuer_params
        .self_signed(issuer_key)
        .map_err(|e| CertGenError::CertBuildFailed(format!("issuer self-sign: {e}")))
}

fn build_leaf_params(
    attestation_ext_der: &[u8],
    keybox: &ParsedKeybox,
    params: &CertGenParams,
) -> Result<CertificateParams> {
    let mut cp = CertificateParams::default();

    // Subject DN
    cp.distinguished_name = if let Some(ref subject_der) = params.cert_subject {
        parse_dn_from_der(subject_der)?
    } else {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Android KeyStore Key");
        dn
    };

    // Serial number
    cp.serial_number = if let Some(ref serial_bytes) = params.cert_serial {
        Some(SerialNumber::from(serial_bytes.clone()))
    } else {
        Some(SerialNumber::from(vec![1u8]))
    };

    // Validity period
    cp.not_before = timestamp_to_datetime(params.cert_not_before)?;
    cp.not_after = if params.cert_not_after == -1 {
        // Fall back to keybox leaf cert's notAfter, or +1 year
        OffsetDateTime::from_unix_timestamp(keybox.leaf_not_after)
            .unwrap_or_else(|_| OffsetDateTime::now_utc() + time::Duration::days(365))
    } else {
        timestamp_to_datetime(params.cert_not_after)?
    };

    // rcgen 0.13.2: IsCa::NoCa (the default) emits neither BasicConstraints nor SKI
    // extension. This matches real Android attestation leaf certs which include neither.
    // No explicit suppression needed — NoCa is a no-op in the extension writer.

    // KeyUsage from purposes
    cp.key_usages = map_key_usages(&params.purposes);

    // Attestation extension (non-critical)
    let mut attest_ext = CustomExtension::from_oid_content(ATTESTATION_OID, attestation_ext_der.to_vec());
    attest_ext.set_criticality(false);
    cp.custom_extensions.push(attest_ext);

    Ok(cp)
}

/// Maps KeyPurpose values to X.509 KeyUsage bits per KeyCreationResult.aidl spec.
/// Only SIGN, DECRYPT, WRAP_KEY, AGREE_KEY, and ATTEST_KEY produce KeyUsage bits.
/// ENCRYPT and VERIFY are intentionally excluded (matches Kotlin CertificateGenerator).
fn map_key_usages(purposes: &[i32]) -> Vec<KeyUsagePurpose> {
    let mut usages = Vec::new();
    for &purpose in purposes {
        match purpose {
            2 => {
                // SIGN -> digitalSignature
                if !usages.contains(&KeyUsagePurpose::DigitalSignature) {
                    usages.push(KeyUsagePurpose::DigitalSignature);
                }
            }
            1 => {
                // DECRYPT -> dataEncipherment
                if !usages.contains(&KeyUsagePurpose::DataEncipherment) {
                    usages.push(KeyUsagePurpose::DataEncipherment);
                }
            }
            5 => {
                // WRAP_KEY -> keyEncipherment
                if !usages.contains(&KeyUsagePurpose::KeyEncipherment) {
                    usages.push(KeyUsagePurpose::KeyEncipherment);
                }
            }
            6 => {
                // AGREE_KEY -> keyAgreement
                if !usages.contains(&KeyUsagePurpose::KeyAgreement) {
                    usages.push(KeyUsagePurpose::KeyAgreement);
                }
            }
            7 => {
                // ATTEST_KEY -> keyCertSign
                if !usages.contains(&KeyUsagePurpose::KeyCertSign) {
                    usages.push(KeyUsagePurpose::KeyCertSign);
                }
            }
            _ => {}
        }
    }
    usages
}

fn timestamp_to_datetime(ts: i64) -> Result<OffsetDateTime> {
    if ts == -1 {
        return Ok(OffsetDateTime::now_utc());
    }
    // Params use milliseconds for validity timestamps
    OffsetDateTime::from_unix_timestamp(ts / 1000)
        .map_err(|e| CertGenError::CertBuildFailed(format!("invalid timestamp {ts}: {e}")))
}

// Parse a DER-encoded X.500 Name into rcgen DistinguishedName.
// We only extract the CN (most common for Android keystore certs).
// If parsing fails, fall back to empty DN.
fn parse_dn_from_der(der: &[u8]) -> Result<DistinguishedName> {
    use x509_cert::name::Name;
    use der::{Decode, Encode};

    let name = Name::from_der(der)
        .map_err(|e| CertGenError::CertBuildFailed(format!("DN parse: {e}")))?;

    let mut dn = DistinguishedName::new();

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid_str = atv.oid.to_string();
            // Map common OIDs to rcgen DnType
            let dn_type = match oid_str.as_str() {
                "2.5.4.3" => DnType::CommonName,
                "2.5.4.6" => DnType::CountryName,
                "2.5.4.7" => DnType::LocalityName,
                "2.5.4.8" => DnType::StateOrProvinceName,
                "2.5.4.10" => DnType::OrganizationName,
                "2.5.4.11" => DnType::OrganizationalUnitName,
                other => DnType::CustomDnType(
                    other.split('.').filter_map(|s| s.parse().ok()).collect(),
                ),
            };

            // Extract the string value from the AttributeValue (ANY type)
            // The value is DER-encoded; try to read it as UTF8String or PrintableString
            let value_bytes = atv.value.to_der()
                .map_err(|e| CertGenError::CertBuildFailed(format!("DN value encode: {e}")))?;
            let value_str = extract_string_from_der_any(&value_bytes);
            dn.push(dn_type, value_str);
        }
    }

    Ok(dn)
}

// Extract a string from a DER-encoded ASN.1 string type (UTF8String, PrintableString, etc.)
fn extract_string_from_der_any(der: &[u8]) -> String {
    if der.len() < 2 {
        return String::new();
    }
    // Tag byte at [0], length at [1..], then content
    let tag = der[0];
    let (content_len, header_len) = if der[1] < 0x80 {
        (der[1] as usize, 2)
    } else {
        let num = (der[1] & 0x7f) as usize;
        if num == 0 || 2 + num > der.len() {
            return String::new();
        }
        let mut len = 0usize;
        for i in 0..num {
            len = (len << 8) | der[2 + i] as usize;
        }
        (len, 2 + num)
    };

    let end = header_len + content_len;
    if end > der.len() {
        return String::new();
    }
    let content = &der[header_len..end];

    match tag {
        0x0C | 0x13 | 0x16 | 0x1A => {
            // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16), VisibleString (0x1A)
            String::from_utf8_lossy(content).into_owned()
        }
        0x1E => {
            // BMPString (UTF-16BE)
            let chars: Vec<u16> = content
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&chars)
        }
        _ => String::from_utf8_lossy(content).into_owned(),
    }
}
