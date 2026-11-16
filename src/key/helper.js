/**
 * @fileoverview Provides helpers methods for key module
 * @module key/helper
 * @access private
 */

import {
  SecretKeyPacket,
  SecretSubkeyPacket,
  SignaturePacket
} from '../packet/index.js';
import enums from '../enums.ts';
import { getPreferredCurveHashAlgo, getHashByteLength, publicKey } from '../crypto/index.js';
import util from '../util.js';
import defaultConfig from '../config.ts';

export async function generateSecretSubkey(options, config) {
  const secretSubkeyPacket = new SecretSubkeyPacket(options.date, config);
  secretSubkeyPacket.packets = null;
  secretSubkeyPacket.algorithm = enums.write(enums.publicKey, options.algorithm);
  await secretSubkeyPacket.generate(options.rsaBits, options.curve);
  await secretSubkeyPacket.computeFingerprintAndKeyID();
  return secretSubkeyPacket;
}

export async function generateSecretKey(options, config) {
  const secretKeyPacket = new SecretKeyPacket(options.date, config);
  secretKeyPacket.packets = null;
  secretKeyPacket.algorithm = enums.write(enums.publicKey, options.algorithm);
  await secretKeyPacket.generate(options.rsaBits, options.curve, options.config);
  await secretKeyPacket.computeFingerprintAndKeyID();
  return secretKeyPacket;
}

/**
 * Returns the valid and non-expired signature that has the latest creation date, while ignoring signatures created in the future.
 * @param {Array<SignaturePacket>} signatures - List of signatures
 * @param {PublicKeyPacket|PublicSubkeyPacket} publicKey - Public key packet to verify the signature
 * @param {module:enums.signature} signatureType - Signature type to determine how to hash the data (NB: for userID signatures,
 *                          `enums.signatures.certGeneric` should be given regardless of the actual trust level)
 * @param {Date} date - Use the given date instead of the current time
 * @param {Object} config - full configuration
 * @returns {Promise<SignaturePacket>} The latest valid signature.
 * @async
 */
export async function getLatestValidSignature(signatures, publicKey, signatureType, dataToVerify, date = new Date(), config) {
  let latestValid;
  let exception;
  for (let i = signatures.length - 1; i >= 0; i--) {
    try {
      if (
        (!latestValid || signatures[i].created >= latestValid.created)
      ) {
        await signatures[i].verify(publicKey, signatureType, dataToVerify, date, undefined, config);
        latestValid = signatures[i];
      }
    } catch (e) {
      exception = e;
    }
  }
  if (!latestValid) {
    throw util.wrapError(
      `Could not find valid ${enums.read(enums.signature, signatureType)} signature in key ${publicKey.getKeyID().toHex()}`
        .replace('certGeneric ', 'self-')
        .replace(/([a-z])([A-Z])/g, (_, $1, $2) => $1 + ' ' + $2.toLowerCase()),
      exception);
  }
  return latestValid;
}

export function isDataExpired(keyPacket, signature, date = new Date()) {
  const normDate = util.normalizeDate(date);
  if (normDate !== null) {
    const expirationTime = getKeyExpirationTime(keyPacket, signature);
    return !(keyPacket.created <= normDate && normDate < expirationTime);
  }
  return false;
}

/**
 * Create Binding signature to the key according to the {@link https://tools.ietf.org/html/rfc4880#section-5.2.1}
 * @param {SecretSubkeyPacket} subkey - Subkey key packet
 * @param {SecretKeyPacket} primaryKey - Primary key packet
 * @param {Object} options
 * @param {Object} config - Full configuration
 */
export async function createBindingSignature(subkey, primaryKey, options, config) {
  const dataToSign = {};
  dataToSign.key = primaryKey;
  dataToSign.bind = subkey;
  const signatureProperties = { signatureType: enums.signature.subkeyBinding };
  if (options.sign) {
    signatureProperties.keyFlags = [enums.keyFlags.signData];
    signatureProperties.embeddedSignature = await createSignaturePacket(dataToSign, [], subkey, {
      signatureType: enums.signature.keyBinding
    }, options.date, undefined, undefined, undefined, config);
  } else {
    signatureProperties.keyFlags = [enums.keyFlags.encryptCommunication | enums.keyFlags.encryptStorage];
  }
  if (options.keyExpirationTime > 0) {
    signatureProperties.keyExpirationTime = options.keyExpirationTime;
    signatureProperties.keyNeverExpires = false;
  }
  const subkeySignaturePacket = await createSignaturePacket(dataToSign, [], primaryKey, signatureProperties, options.date, undefined, undefined, undefined, config);
  return subkeySignaturePacket;
}

/**
 * Returns the preferred signature hash algorithm for a set of keys.
 * @param {Array<Key>} [targetKeys] - The keys to get preferences from
 * @param {SecretKeyPacket|SecretSubkeyPacket} signingKeyPacket - key packet used for signing
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Object} [targetUserID] - User IDs corresponding to `targetKeys` to get preferences from
 * @param {Object} config - full configuration
 * @returns {Promise<enums.hash>}
 * @async
 */
export async function getPreferredHashAlgo(targetKeys, signingKeyPacket, date = new Date(), targetUserIDs = [], config) {
  /**
   * If `preferredSenderAlgo` appears in the prefs of all recipients, we pick it; otherwise, we use the
   * strongest supported algo (`defaultAlgo` is always implicitly supported by all keys).
   * if no keys are available, `preferredSenderAlgo` is returned.
   * For ECC signing key, the curve preferred hash is taken into account as well (see logic below).
   */
  const defaultAlgo = enums.hash.sha256; // MUST implement
  const preferredSenderAlgo = config.preferredHashAlgorithm;

  const supportedAlgosPerTarget = await Promise.all(targetKeys.map(async (key, i) => {
    const selfCertification = await key.getPrimarySelfSignature(date, targetUserIDs[i], config);
    const targetPrefs = selfCertification.preferredHashAlgorithms;
    return targetPrefs || [];
  }));
  const supportedAlgosMap = new Map(); // use Map over object to preserve numeric keys
  for (const supportedAlgos of supportedAlgosPerTarget) {
    for (const hashAlgo of supportedAlgos) {
      try {
        // ensure that `hashAlgo` is recognized/implemented by us, otherwise e.g. `getHashByteLength` will throw later on
        const supportedAlgo = enums.write(enums.hash, hashAlgo);
        supportedAlgosMap.set(
          supportedAlgo,
          supportedAlgosMap.has(supportedAlgo) ? supportedAlgosMap.get(supportedAlgo) + 1 : 1
        );
      } catch {}
    }
  }
  const isSupportedHashAlgo = hashAlgo => targetKeys.length === 0 || supportedAlgosMap.get(hashAlgo) === targetKeys.length || hashAlgo === defaultAlgo;
  const getStrongestSupportedHashAlgo = () => {
    if (supportedAlgosMap.size === 0) {
      return defaultAlgo;
    }
    const sortedHashAlgos = Array.from(supportedAlgosMap.keys())
      .filter(hashAlgo => isSupportedHashAlgo(hashAlgo))
      .sort((algoA, algoB) => getHashByteLength(algoA) - getHashByteLength(algoB));
    const strongestHashAlgo = sortedHashAlgos[0];
    // defaultAlgo is always implicitly supported, and might be stronger than the rest
    return getHashByteLength(strongestHashAlgo) >= getHashByteLength(defaultAlgo) ? strongestHashAlgo : defaultAlgo;
  };

  const eccAlgos = new Set([
    enums.publicKey.ecdsa,
    enums.publicKey.eddsaLegacy,
    enums.publicKey.ed25519,
    enums.publicKey.ed448
  ]);

  const pqcAlgos = new Set([
    enums.publicKey.mldsa65Ed25519
  ]);

  if (eccAlgos.has(signingKeyPacket.algorithm)) {
    // For ECC, the returned hash algo MUST be at least as strong as `preferredCurveHashAlgo`, see:
    // - ECDSA: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.2-5
    // - EdDSALegacy: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.3-3
    // - Ed25519: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.4-4
    // - Ed448: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.5-4
    // Hence, we return the `preferredHashAlgo` as long as it's supported and strong enough;
    // Otherwise, we look at the strongest supported algo, and ultimately fallback to the curve
    // preferred algo, even if not supported by all targets.
    const preferredCurveAlgo = getPreferredCurveHashAlgo(signingKeyPacket.algorithm, signingKeyPacket.publicParams.oid);

    const preferredSenderAlgoIsSupported = isSupportedHashAlgo(preferredSenderAlgo);
    const preferredSenderAlgoStrongerThanCurveAlgo = getHashByteLength(preferredSenderAlgo) >= getHashByteLength(preferredCurveAlgo);

    if (preferredSenderAlgoIsSupported && preferredSenderAlgoStrongerThanCurveAlgo) {
      return preferredSenderAlgo;
    } else {
      const strongestSupportedAlgo = getStrongestSupportedHashAlgo();
      return getHashByteLength(strongestSupportedAlgo) >= getHashByteLength(preferredCurveAlgo) ?
        strongestSupportedAlgo :
        preferredCurveAlgo;
    }
  } else if (pqcAlgos.has(signingKeyPacket.algorithm)) {
    // For PQC, the returned hash algo MUST be at least 256 bit long, see:
    // https://www.rfc-editor.org/rfc/rfc9980.html#section-9.4 .
    // Hence, we return the `preferredHashAlgo` as long as it's supported and long enough;
    // Otherwise, we look at the strongest supported algo, and ultimately fallback the default algo (SHA-256).
    const preferredSenderAlgoIsSupported = isSupportedHashAlgo(preferredSenderAlgo) && publicKey.postQuantum.signature.isCompatibleHashAlgo(signingKeyPacket.algorithm, preferredSenderAlgo);

    if (preferredSenderAlgoIsSupported) {
      return preferredSenderAlgo;
    } else {
      const strongestSupportedAlgo = getStrongestSupportedHashAlgo();
      return publicKey.postQuantum.signature.isCompatibleHashAlgo(signingKeyPacket.algorithm, strongestSupportedAlgo) ?
        strongestSupportedAlgo :
        defaultAlgo;
    }
  }

  // `preferredSenderAlgo` may be weaker than the default, but we do not guard against this,
  // since it was manually set by the sender.
  return isSupportedHashAlgo(preferredSenderAlgo) ? preferredSenderAlgo : getStrongestSupportedHashAlgo();
}

/**
 * Returns the preferred compression algorithm for a set of keys
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<module:enums.compression>} Preferred compression algorithm
 * @async
 */
export async function getPreferredCompressionAlgo(keys = [], date = new Date(), userIDs = [], config = defaultConfig) {
  const defaultAlgo = enums.compression.uncompressed;
  const preferredSenderAlgo = config.preferredCompressionAlgorithm;

  // if preferredSenderAlgo appears in the prefs of all recipients, we pick it
  // otherwise we use the default algo
  // if no keys are available, preferredSenderAlgo is returned
  const senderAlgoSupport = await Promise.all(keys.map(async function(key, i) {
    const selfCertification = await key.getPrimarySelfSignature(date, userIDs[i], config);
    const recipientPrefs = selfCertification.preferredCompressionAlgorithms;
    return !!recipientPrefs && recipientPrefs.indexOf(preferredSenderAlgo) >= 0;
  }));
  return senderAlgoSupport.every(Boolean) ? preferredSenderAlgo : defaultAlgo;
}

/**
 * Returns the preferred symmetric and AEAD algorithm (if any) for a set of keys
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<{ symmetricAlgo: module:enums.symmetric, aeadAlgo: module:enums.aead | undefined }>} Object containing the preferred symmetric algorithm, and the preferred AEAD algorithm, or undefined if CFB is preferred
 * @async
 */
export async function getPreferredCipherSuite(keys = [], date = new Date(), userIDs = [], config = defaultConfig) {
  const selfSigs = await Promise.all(keys.map((key, i) => key.getPrimarySelfSignature(date, userIDs[i], config)));
  const withAEAD = keys.length ?
    selfSigs.every(selfSig => selfSig.features && (selfSig.features[0] & enums.features.seipdv2)) :
    config.aeadProtect;

  if (withAEAD) {
    const defaultCipherSuite = { symmetricAlgo: enums.symmetric.aes128, aeadAlgo: enums.aead.ocb };
    const desiredCipherSuites = [
      { symmetricAlgo: config.preferredSymmetricAlgorithm, aeadAlgo: config.preferredAEADAlgorithm },
      { symmetricAlgo: config.preferredSymmetricAlgorithm, aeadAlgo: enums.aead.ocb },
      { symmetricAlgo: enums.symmetric.aes128, aeadAlgo: config.preferredAEADAlgorithm }
    ];
    for (const desiredCipherSuite of desiredCipherSuites) {
      if (selfSigs.every(selfSig => selfSig.preferredCipherSuites && selfSig.preferredCipherSuites.some(
        cipherSuite => cipherSuite[0] === desiredCipherSuite.symmetricAlgo && cipherSuite[1] === desiredCipherSuite.aeadAlgo
      ))) {
        return desiredCipherSuite;
      }
    }
    return defaultCipherSuite;
  }
  const defaultSymAlgo = enums.symmetric.aes128;
  const desiredSymAlgo = config.preferredSymmetricAlgorithm;
  return {
    symmetricAlgo: selfSigs.every(selfSig => selfSig.preferredSymmetricAlgorithms && selfSig.preferredSymmetricAlgorithms.includes(desiredSymAlgo)) ?
      desiredSymAlgo :
      defaultSymAlgo,
    aeadAlgo: undefined
  };
}

/**
 * Create signature packet
 * @param {Object} dataToSign - Contains packets to be signed
 * @param {Array<Key>} recipientKeys - keys to get preferences from
 * @param  {SecretKeyPacket|
 *          SecretSubkeyPacket}              signingKeyPacket secret key packet for signing
 * @param {Object} [signatureProperties] - Properties to write on the signature packet before signing
 * @param {Date} [date] - Override the creationtime of the signature
 * @param {Object} [userID] - User ID
 * @param {Array} [notations] - Notation Data to add to the signature, e.g. [{ name: 'test@example.org', value: new TextEncoder().encode('test'), humanReadable: true, critical: false }]
 * @param {Object} [detached] - Whether to create a detached signature packet
 * @param {Object} config - full configuration
 * @returns {Promise<SignaturePacket>} Signature packet.
 */
export async function createSignaturePacket(dataToSign, recipientKeys, signingKeyPacket, signatureProperties, date, recipientUserIDs, notations = [], detached = false, config) {
  if (signingKeyPacket.isDummy()) {
    throw new Error('Cannot sign with a gnu-dummy key.');
  }
  if (!signingKeyPacket.isDecrypted()) {
    throw new Error('Signing key is not decrypted.');
  }
  const signaturePacket = new SignaturePacket();
  Object.assign(signaturePacket, signatureProperties);
  signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
  signaturePacket.hashAlgorithm = await getPreferredHashAlgo(recipientKeys, signingKeyPacket, date, recipientUserIDs, config);
  signaturePacket.rawNotations = [...notations];
  await signaturePacket.sign(signingKeyPacket, dataToSign, date, detached, config);
  return signaturePacket;
}

/**
 * Merges signatures from source[attr] to dest[attr]
 * @param {Object} source
 * @param {Object} dest
 * @param {String} attr
 * @param {Date} [date] - date to use for signature expiration check, instead of the current time
 * @param {Function} [checkFn] - signature only merged if true
 */
export async function mergeSignatures(source, dest, attr, date = new Date(), checkFn) {
  source = source[attr];
  if (source) {
    if (!dest[attr].length) {
      dest[attr] = source;
    } else {
      await Promise.all(source.map(async function(sourceSig) {
        if (!sourceSig.isExpired(date) && (!checkFn || await checkFn(sourceSig)) &&
            !dest[attr].some(function(destSig) {
              return util.equalsUint8Array(destSig.writeParams(), sourceSig.writeParams());
            })) {
          dest[attr].push(sourceSig);
        }
      }));
    }
  }
}

/**
 * Returns the keys that the given key's owner has declared as authorized revokers.
 *
 * Only direct-key self-signatures (Type ID 0x1F) are considered: per RFC4880 5.2.3.15, that is the
 * location of the Revocation Key subpacket, and its use in other self-signatures is unspecified.
 * The declarations are gathered regardless of the self-signature's expiration date, so that a designated
 * revoker remains available even after the self-signature that declared it has expired.
 *
 * @param {Key} key - The key to inspect
 * @param {Object} config - Full configuration
 * @returns {Promise<Array<{
 *   revocationKeyFingerprint: Uint8Array,
 *   revocationKeyAlgorithm: module:enums.publicKey,
 *   revocationKeyClass: Integer,
 *   created: Date
 * }>>} The declared revokers, deduplicated by fingerprint (keeping the earliest declaration).
 * @async
 */
export async function getDesignatedRevocationKeys(key, config = defaultConfig) {
  const primaryKey = key.keyPacket;
  if (!primaryKey) {
    return [];
  }
  const primaryKeyID = primaryKey.getKeyID();
  // Per RFC4880 5.2.3.15, the revocation key subpacket is only found on a Direct Key self-signature.
  // Its use elsewhere is unspecified, hence it is rejected outright when parsing/verifying the signature
  // (see `SignaturePacket#verify`), and not considered here.
  const selfSignatures = key.directSignatures
    .filter(sig => sig.signatureType === enums.signature.key)
    .map(sig => ({ sig, dataToVerify: { key: primaryKey } }));

  const declarations = new Map();
  await Promise.all(selfSignatures.map(async ({ sig, dataToVerify }) => {
    if (sig.revocationKeyClass === null || sig.revocationKeyFingerprint === null ||
        sig.revocationKeyAlgorithm === null) {
      return;
    }
    // The class octet must have bit 0x80 set, see RFC4880 5.2.3.15
    if (!(sig.revocationKeyClass & 0x80)) {
      return;
    }
    // Only the key owner can authorize a revoker
    if (!sig.issuerKeyID.equals(primaryKeyID)) {
      return;
    }
    try {
      // The declaration is checked for cryptographic validity only: its expiration date is
      // intentionally ignored, so that the revoker remains available after the declaration expires.
      await sig.verify(primaryKey, enums.signature.key, dataToVerify, null, false, config);
    } catch {
      return;
    }
    // The declaration predates the revocation it authorizes. We keep the earliest declaration
    // per fingerprint, as that is the one that matters for the authorization time check.
    const fingerprintHex = util.uint8ArrayToHex(sig.revocationKeyFingerprint);
    const existing = declarations.get(fingerprintHex);
    if (!existing || sig.created < existing.created) {
      declarations.set(fingerprintHex, {
        revocationKeyFingerprint: sig.revocationKeyFingerprint,
        revocationKeyAlgorithm: sig.revocationKeyAlgorithm,
        revocationKeyClass: sig.revocationKeyClass,
        created: sig.created
      });
    }
  }));
  return [...declarations.values()];
}

/**
 * Returns the configured public key (packet) matching the given revocation key fingerprint, if any.
 * @param {Uint8Array} fingerprint - Revocation key fingerprint, as declared in the Revocation Key subpacket
 * @param {Object} config - Full configuration
 * @returns {PublicKeyPacket|SecretKeyPacket|null} The matching revoker key packet, or null.
 */
export function getConfiguredRevokerKeyPacket(fingerprint, config) {
  const candidates = config.designatedRevokers || [];
  for (const candidate of candidates) {
    const keyPacket = candidate && (candidate.keyPacket || candidate);
    if (!keyPacket || typeof keyPacket.getFingerprintBytes !== 'function') {
      continue;
    }
    if (util.equalsUint8Array(keyPacket.getFingerprintBytes(), fingerprint)) {
      return keyPacket;
    }
  }
  return null;
}

/**
 * Returns the public key packet of the designated revoker that authorizes the given revocation signature,
 * if the revoker key is available via `config.designatedRevokers`.
 *
 * The revocation is only authorized if:
 * - the declaration has the 0x80 class bit set;
 * - the declaration is not newer than the revocation signature (a revoker cannot retroactively be authorized);
 * - the declared algorithm matches the algorithm of the revocation signature;
 * - the configured revoker key has the declared fingerprint, and its key ID matches the signature issuer.
 *
 * @param {Object} declaration - A declaration returned by {@link getDesignatedRevocationKeys}
 * @param {SignaturePacket} revocationSignature - The third-party revocation signature
 * @param {Object} config - Full configuration
 * @returns {PublicKeyPacket|SecretKeyPacket|null} The revoker key packet, or null if not authorized.
 */
export function getDesignatedRevokerKeyPacket(declaration, revocationSignature, config) {
  if (!(declaration.revocationKeyClass & 0x80)) {
    return null;
  }
  if (declaration.created > revocationSignature.created) {
    return null;
  }
  if (declaration.revocationKeyAlgorithm !== revocationSignature.publicKeyAlgorithm) {
    return null;
  }
  const revokerKeyPacket = getConfiguredRevokerKeyPacket(declaration.revocationKeyFingerprint, config);
  if (!revokerKeyPacket || typeof revokerKeyPacket.getKeyID !== 'function') {
    return null;
  }
  if (!revocationSignature.issuerKeyID.equals(revokerKeyPacket.getKeyID())) {
    return null;
  }
  return revokerKeyPacket;
}

/**
 * Normalizes a designated revoker declaration to a fingerprint and public key algorithm.
 * The revoker can be given as a key object, or as a hex fingerprint. In the latter case, the revoker's
 * public key must also be listed in `config.designatedRevokers`, so that its algorithm can be determined.
 * @param {String|Key|Subkey|PublicKeyPacket|SecretKeyPacket} revoker - Designated revoker identifier
 * @param {Object} config - Full configuration
 * @returns {{ fingerprint: Uint8Array, algorithm: module:enums.publicKey }}
 */
export function resolveDesignatedRevoker(revoker, config) {
  const keyPacket = revoker && (revoker.keyPacket || revoker);
  if (keyPacket && typeof keyPacket.getFingerprintBytes === 'function' && typeof keyPacket.getKeyID === 'function') {
    return {
      fingerprint: keyPacket.getFingerprintBytes(),
      algorithm: keyPacket.algorithm
    };
  }
  if (util.isString(revoker)) {
    const fingerprintHex = revoker.replace(/\s/g, '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(fingerprintHex) || fingerprintHex.length % 2 !== 0) {
      throw new Error('Invalid designated revoker fingerprint');
    }
    const fingerprint = util.hexToUint8Array(fingerprintHex);
    const configuredKeyPacket = getConfiguredRevokerKeyPacket(fingerprint, config);
    if (!configuredKeyPacket) {
      throw new Error('The designated revoker key is unknown: pass the revoker key object, or provide it via `config.designatedRevokers`');
    }
    return {
      fingerprint,
      algorithm: configuredKeyPacket.algorithm
    };
  }
  throw new Error('Invalid designated revoker: expected a key object or a hex fingerprint');
}

/**
 * Checks if a given certificate or binding signature is revoked
 * @param  {SecretKeyPacket|
 *          PublicKeyPacket}        primaryKey   The primary key packet
 * @param {Object} dataToVerify - The data to check
 * @param {Array<SignaturePacket>} revocations - The revocation signatures to check
 * @param {SignaturePacket} signature - The certificate or signature to check
 * @param  {PublicSubkeyPacket|
 *          SecretSubkeyPacket|
 *          PublicKeyPacket|
 *          SecretKeyPacket} key, optional The key packet to verify the signature, instead of the primary key
 * @param {Date} date - Use the given date instead of the current time
 * @param {Object} config - Full configuration
 * @param {Array<Object>} [designatedRevocationKeys] - Revokers declared by the primary key's self-signatures,
 *        as returned by {@link getDesignatedRevocationKeys}
 * @returns {Promise<Boolean>} True if the signature revokes the data.
 * @async
 */
export async function isDataRevoked(primaryKey, signatureType, dataToVerify, revocations, signature, key, date = new Date(), config, designatedRevocationKeys = []) {
  key = key || primaryKey;
  const revocationKeyIDs = [];
  let revokedByDesignatedRevoker = false;
  // Whether `signature` (if any) belongs to the primary key, and can therefore be revoked by a designated revoker.
  // A designated revoker cannot revoke a third party's certification of this key.
  const isSelfIssuedSignature = !signature || signature.issuerKeyID.equals(primaryKey.getKeyID());
  // Per RFC4880 5.2.1, a designated revoker is only authorized to issue key revocation (0x20) and
  // subkey revocation (0x28) signatures; it cannot revoke User ID certifications.
  const canBeRevokedByDesignatedRevoker = isSelfIssuedSignature &&
    (signatureType === enums.signature.keyRevocation || signatureType === enums.signature.subkeyRevocation);
  await Promise.all(revocations.map(async function(revocationSignature) {
    try {
      // When no target signature is given, we are checking whether the primary key itself is revoked,
      // hence a self revocation is one issued by the primary key.
      const revokedIssuerKeyID = signature ? signature.issuerKeyID : primaryKey.getKeyID();
      const isSelfRevocation = revocationSignature.issuerKeyID.equals(revokedIssuerKeyID);
      const isHardRevocation = ![
        enums.reasonForRevocation.keyRetired,
        enums.reasonForRevocation.keySuperseded,
        enums.reasonForRevocation.userIDInvalid
      ].includes(revocationSignature.reasonForRevocationFlag);
      const verificationDate = isHardRevocation ? null : date;

      if (isSelfRevocation) {
        await revocationSignature.verify(
          key, signatureType, dataToVerify, verificationDate, false, config
        );
        // TODO get an identifier of the revoked object instead
        revocationKeyIDs.push(revocationSignature.issuerKeyID);
        return;
      }

      // Third-party revocation signatures are ignored, to avoid a malicious actor revoking a key
      // that did not authorize them. The only exception are revokers explicitly declared by the key owner.
      if (!canBeRevokedByDesignatedRevoker) {
        return;
      }
      for (const declaration of designatedRevocationKeys) {
        const revokerKeyPacket = getDesignatedRevokerKeyPacket(declaration, revocationSignature, config);
        if (!revokerKeyPacket) {
          continue;
        }
        await revocationSignature.verify(
          revokerKeyPacket, signatureType, dataToVerify, verificationDate, false, config
        );
        revokedByDesignatedRevoker = true;
        revocationKeyIDs.push(revocationSignature.issuerKeyID);
        return;
      }
    } catch {}
  }));
  // TODO further verify that this is the signature that should be revoked
  if (signature) {
    signature.revoked = revocationKeyIDs.some(keyID => keyID.equals(signature.issuerKeyID)) || revokedByDesignatedRevoker ? true :
      signature.revoked || false;
    return signature.revoked;
  }
  return revocationKeyIDs.length > 0;
}

/**
 * Returns key expiration time based on the given certification signature.
 * The expiration time of the signature is ignored.
 * @param {PublicSubkeyPacket|PublicKeyPacket} keyPacket - key to check
 * @param {SignaturePacket} signature - signature to process
 * @returns {Date|Infinity} expiration time or infinity if the key does not expire
 */
export function getKeyExpirationTime(keyPacket, signature) {
  let expirationTime;
  // check V4 expiration time
  if (signature.keyNeverExpires === false) {
    expirationTime = keyPacket.created.getTime() + signature.keyExpirationTime * 1000;
  }
  return expirationTime ? new Date(expirationTime) : Infinity;
}

export function sanitizeKeyOptions(options, subkeyDefaults = {}) {
  options.type = options.type || subkeyDefaults.type;
  options.curve = options.curve || subkeyDefaults.curve;
  options.rsaBits = options.rsaBits || subkeyDefaults.rsaBits;
  options.keyExpirationTime = options.keyExpirationTime !== undefined ? options.keyExpirationTime : subkeyDefaults.keyExpirationTime;
  options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
  options.date = options.date || subkeyDefaults.date;

  options.sign = options.sign || false;

  switch (options.type) {
    case 'pqc':
      if (options.sign) {
        options.algorithm = enums.publicKey.mldsa65Ed25519;
      } else {
        options.algorithm = enums.publicKey.mlkem768X25519;
      }
      break;
    case 'ecc': // NB: this case also handles legacy eddsa and x25519 keys, based on `options.curve`
      try {
        options.curve = enums.write(enums.curve, options.curve);
      } catch {
        throw new Error('Unknown curve');
      }
      if (options.curve === enums.curve.ed25519Legacy || options.curve === enums.curve.curve25519Legacy ||
        options.curve === 'ed25519' || options.curve === 'curve25519') { // keep support for curve names without 'Legacy' addition, for now
        options.curve = options.sign ? enums.curve.ed25519Legacy : enums.curve.curve25519Legacy;
      }
      if (options.sign) {
        options.algorithm = options.curve === enums.curve.ed25519Legacy ? enums.publicKey.eddsaLegacy : enums.publicKey.ecdsa;
      } else {
        options.algorithm = enums.publicKey.ecdh;
      }
      break;
    case 'curve25519':
      options.algorithm = options.sign ? enums.publicKey.ed25519 : enums.publicKey.x25519;
      break;
    case 'curve448':
      options.algorithm = options.sign ? enums.publicKey.ed448 : enums.publicKey.x448;
      break;
    case 'rsa':
      options.algorithm = enums.publicKey.rsaEncryptSign;
      break;
    default:
      throw new Error(`Unsupported key type ${options.type}`);
  }
  return options;
}

export function validateSigningKeyPacket(keyPacket, signature, config) {
  switch (keyPacket.algorithm) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign:
    case enums.publicKey.dsa:
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
    case enums.publicKey.mldsa65Ed25519:
      if (!signature.keyFlags && !config.allowMissingKeyFlags) {
        throw new Error('None of the key flags is set: consider passing `config.allowMissingKeyFlags`');
      }
      return !signature.keyFlags ||
        (signature.keyFlags[0] & enums.keyFlags.signData) !== 0;
    default:
      return false;
  }
}

export function validateEncryptionKeyPacket(keyPacket, signature, config) {
  switch (keyPacket.algorithm) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.elgamal:
    case enums.publicKey.ecdh:
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
    case enums.publicKey.mlkem768X25519:
      if (!signature.keyFlags && !config.allowMissingKeyFlags) {
        throw new Error('None of the key flags is set: consider passing `config.allowMissingKeyFlags`');
      }
      return !signature.keyFlags ||
        (signature.keyFlags[0] & enums.keyFlags.encryptCommunication) !== 0 ||
        (signature.keyFlags[0] & enums.keyFlags.encryptStorage) !== 0;
    default:
      return false;
  }
}

export function validateDecryptionKeyPacket(keyPacket, signature, config) {
  if (!signature.keyFlags && !config.allowMissingKeyFlags) {
    throw new Error('None of the key flags is set: consider passing `config.allowMissingKeyFlags`');
  }

  switch (keyPacket.algorithm) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.elgamal:
    case enums.publicKey.ecdh:
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
    case enums.publicKey.mlkem768X25519: {
      const isValidSigningKeyPacket = !signature.keyFlags || (signature.keyFlags[0] & enums.keyFlags.signData) !== 0;
      if (isValidSigningKeyPacket && config.allowInsecureDecryptionWithSigningKeys) {
        // This is only relevant for RSA keys, all other signing algorithms cannot decrypt
        return true;
      }

      return !signature.keyFlags ||
      (signature.keyFlags[0] & enums.keyFlags.encryptCommunication) !== 0 ||
      (signature.keyFlags[0] & enums.keyFlags.encryptStorage) !== 0;
    }
    default:
      return false;
  }
}

/**
 * Check key against blacklisted algorithms and minimum strength requirements.
 * @param {SecretKeyPacket|PublicKeyPacket|
 *        SecretSubkeyPacket|PublicSubkeyPacket} keyPacket
 * @param {Config} config
 * @throws {Error} if the key packet does not meet the requirements
 */
export function checkKeyRequirements(keyPacket, config) {
  const keyAlgo = enums.write(enums.publicKey, keyPacket.algorithm);
  const algoInfo = keyPacket.getAlgorithmInfo();
  if (config.rejectPublicKeyAlgorithms.has(keyAlgo)) {
    throw new Error(`${algoInfo.algorithm} keys are considered too weak.`);
  }
  switch (keyAlgo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign:
    case enums.publicKey.rsaEncrypt:
      if (algoInfo.bits < config.minRSABits) {
        throw new Error(`RSA keys shorter than ${config.minRSABits} bits are considered too weak.`);
      }
      break;
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
    case enums.publicKey.ecdh:
      if (config.rejectCurves.has(algoInfo.curve)) {
        throw new Error(`Support for ${algoInfo.algorithm} keys using curve ${algoInfo.curve} is disabled.`);
      }
      break;
    default:
      break;
  }
}
