import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import-x/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';
import util from '../../src/util.js';

const now = Date.now();
const keyDate = new Date(now - 100 * 24 * 3600 * 1000);
const declarationDate = new Date(now - 90 * 24 * 3600 * 1000);
const revocationDate = new Date(now - 10 * 24 * 3600 * 1000);

async function generateTestKey(name) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    userIDs: [{ name, email: `${name.toLowerCase()}@example.com` }],
    type: 'ecc',
    date: keyDate,
    format: 'object'
  });
  return { privateKey, publicKey };
}

/**
 * Builds a third-party signature packet with the low-level API, using the classes exposed by the
 * library under test (instead of importing internals, which would mix module instances).
 */
async function createThirdPartySignaturePacket(signingKeyPacket, signatureType, dataToSign, date, config, properties = {}) {
  const signaturePacket = new openpgp.SignaturePacket();
  Object.assign(signaturePacket, properties);
  signaturePacket.signatureType = signatureType;
  signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
  signaturePacket.hashAlgorithm = openpgp.enums.hash.sha256;
  await signaturePacket.sign(signingKeyPacket, dataToSign, date, false, config);
  return signaturePacket;
}

/**
 * Builds a `keyRevocation` signature over `key` with the given signing key.
 */
async function createKeyRevocationSignature(key, signingKeyPacket, date, config) {
  return createThirdPartySignaturePacket(signingKeyPacket, openpgp.enums.signature.keyRevocation, { key: key.keyPacket }, date, config, {
    reasonForRevocationFlag: openpgp.enums.reasonForRevocation.keyCompromised,
    reasonForRevocationString: 'Designated revoker test'
  });
}

export default () => describe('Designated revocation keys', function() {
  let target;
  let revoker;
  let outsider;

  // Keys are regenerated for each test: `key.clone()` is shallow, hence signatures that cache their
  // revocation status are shared across clones.
  beforeEach(async function() {
    target = await generateTestKey('target');
    revoker = await generateTestKey('revoker');
    outsider = await generateTestKey('outsider');
  });

  it('addRevoker() stores the declaration in a direct-key self-signature', async function() {
    const declared = await target.privateKey.addRevoker(revoker.publicKey, declarationDate);
    const revokers = await declared.getDesignatedRevokers();
    expect(revokers).to.have.length(1);
    expect(util.uint8ArrayToHex(revokers[0].revocationKeyFingerprint)).to.equal(revoker.publicKey.getFingerprint());
    expect(revokers[0].revocationKeyClass).to.equal(0x80);
    expect(revokers[0].revocationKeyAlgorithm).to.equal(revoker.publicKey.keyPacket.algorithm);
    expect(declared.directSignatures).to.have.length(1);
    expect(declared.directSignatures[0].signatureType).to.equal(openpgp.enums.signature.key);
    // the original key is not modified
    expect(target.privateKey.directSignatures).to.have.length(0);
    // undeclared keys have no revokers
    expect(await outsider.privateKey.getDesignatedRevokers()).to.have.length(0);
  });

  it('addRevoker() accepts a hex fingerprint when the revoker key is provided via config', async function() {
    const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
    const declared = await target.privateKey.addRevoker(revoker.publicKey.getFingerprint(), declarationDate, config);
    const revokers = await declared.getDesignatedRevokers();
    expect(util.uint8ArrayToHex(revokers[0].revocationKeyFingerprint)).to.equal(revoker.publicKey.getFingerprint());
    // without the revoker key, the algorithm of the revoker is unknown
    await expect(
      target.privateKey.addRevoker(revoker.publicKey.getFingerprint(), declarationDate)
    ).to.be.rejectedWith(/designated revoker key is unknown/);
  });

  describe('declared revoker key', function() {
    let declaredKey;

    beforeEach(async function() {
      declaredKey = await target.privateKey.addRevoker(revoker.publicKey, declarationDate);
    });

    it('the third-party revocation signature is honoured when the revoker key is configured', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const revocationCertificate = await declaredKey.getDesignatedRevocationCertificate(
        revoker.privateKey, {}, revocationDate, config
      );
      const revokedKey = await declaredKey.applyRevocationCertificate(revocationCertificate, revocationDate, config);

      expect(revokedKey.revocationSignatures).to.have.length(1);
      expect(await revokedKey.isRevoked(null, null, revocationDate, config)).to.equal(true);
      await expect(revokedKey.verifyPrimaryKey(revocationDate, {}, config)).to.be.rejectedWith('Primary key is revoked');
      await expect(
        revokedKey.toPublic().getEncryptionKey(undefined, revocationDate, {}, config)
      ).to.be.rejectedWith('Primary key is revoked');
    });

    it('the same revocation signature is ignored when the revoker key is not configured', async function() {
      const configured = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const unconfigured = { ...openpgp.config };
      const revocationCertificate = await declaredKey.getDesignatedRevocationCertificate(
        revoker.privateKey, {}, revocationDate, configured
      );
      // applying the certificate requires the revoker key
      await expect(
        declaredKey.applyRevocationCertificate(revocationCertificate, revocationDate, unconfigured)
      ).to.be.rejectedWith('Revocation signature does not match key');
      // a key block carrying the signature (as received from a keyserver) is not considered revoked either
      const receivedKey = declaredKey.clone();
      receivedKey.revocationSignatures.push(
        await createKeyRevocationSignature(declaredKey, revoker.privateKey.keyPacket, revocationDate, configured)
      );
      expect(await receivedKey.isRevoked(null, null, revocationDate, unconfigured)).to.equal(false);
      await receivedKey.verifyPrimaryKey(revocationDate, {}, unconfigured);
    });

    it('a revocation signature issued by an undeclared third party is ignored', async function() {
      const config = { ...openpgp.config, designatedRevokers: [outsider.publicKey] };
      const receivedKey = declaredKey.clone();
      receivedKey.revocationSignatures.push(
        await createKeyRevocationSignature(declaredKey, outsider.privateKey.keyPacket, revocationDate, config)
      );
      expect(await receivedKey.isRevoked(null, null, revocationDate, config)).to.equal(false);
      await receivedKey.verifyPrimaryKey(revocationDate, {}, config);
    });

    it('the revoker cannot revoke a third-party certification of the key', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      // the outsider certifies a user ID of the target key
      const certifiedKey = await declaredKey.signPrimaryUser([outsider.privateKey], revocationDate, undefined, config);
      const user = certifiedKey.users[0];
      const otherCertification = user.otherCertifications[0];
      expect(otherCertification).to.exist;
      // the declared revoker issues a certification revocation over it
      const revocationSignature = await createThirdPartySignaturePacket(
        revoker.privateKey.keyPacket, openpgp.enums.signature.certRevocation,
        { userID: user.userID, key: certifiedKey.keyPacket }, revocationDate, config, {
          reasonForRevocationFlag: openpgp.enums.reasonForRevocation.userIDInvalid,
          reasonForRevocationString: ''
        }
      );
      const receivedKey = certifiedKey.clone();
      receivedKey.users[0].revocationSignatures.push(revocationSignature);

      expect(await receivedKey.users[0].isRevoked(otherCertification, undefined, revocationDate, config)).to.equal(false);
    });

    it('the revoker can revoke a subkey, which then cannot be used for encryption', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const encryptionSubkey = declaredKey.subkeys[0];
      expect(encryptionSubkey).to.exist;
      const revocationSignature = await createThirdPartySignaturePacket(
        revoker.privateKey.keyPacket, openpgp.enums.signature.subkeyRevocation,
        { key: declaredKey.keyPacket, bind: encryptionSubkey.keyPacket }, revocationDate, config, {
          reasonForRevocationFlag: openpgp.enums.reasonForRevocation.keyCompromised,
          reasonForRevocationString: ''
        }
      );

      const receivedKey = declaredKey.clone();

      // the subkey of the unrevoked key is still usable
      const message = await openpgp.createMessage({ text: 'hello' });
      await openpgp.encrypt({ message, encryptionKeys: declaredKey.toPublic(), config });

      receivedKey.subkeys[0].revocationSignatures.push(revocationSignature);

      await expect(receivedKey.toPublic().getEncryptionKey(undefined, revocationDate, {}, config))
        .to.be.rejectedWith(/Subkey is revoked/);
      await expect(
        openpgp.encrypt({ message, encryptionKeys: receivedKey.toPublic(), config })
      ).to.be.rejectedWith(/Subkey is revoked/);
    });

    it('a revocation signature older than the declaration is ignored', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      // declaration is created on `revocationDate`, the revoker signature predates it
      const declaredLater = await target.privateKey.addRevoker(revoker.publicKey, revocationDate);
      const receivedKey = declaredLater.clone();
      receivedKey.revocationSignatures.push(
        await createKeyRevocationSignature(declaredLater, revoker.privateKey.keyPacket, declarationDate, config)
      );
      expect(await receivedKey.isRevoked(null, null, revocationDate, config)).to.equal(false);
    });

    it('the generated certificate embeds the revoked key, for interoperability with GnuPG', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const revocationCertificate = await declaredKey.getDesignatedRevocationCertificate(
        revoker.privateKey, {}, revocationDate, config
      );
      const { data } = await openpgp.unarmor(revocationCertificate);
      const packets = await openpgp.PacketList.fromBinary(data, {
        [openpgp.enums.packet.publicKey]: openpgp.PublicKeyPacket,
        [openpgp.enums.packet.signature]: openpgp.SignaturePacket
      }, config);
      // the target key packet comes first, followed by the revocation signature
      expect(packets.map(packet => packet.constructor.tag))
        .to.deep.equal([openpgp.enums.packet.publicKey, openpgp.enums.packet.signature]);
      expect(packets[0].hasSameFingerprintAs(declaredKey.keyPacket)).to.be.true;
      expect(packets[1].signatureType).to.equal(openpgp.enums.signature.keyRevocation);
      expect(packets[1].issuerKeyID.equals(revoker.publicKey.getKeyID())).to.be.true;
    });

    it('a certificate for a different key is rejected', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const otherTarget = await generateTestKey('other');
      const otherDeclared = await otherTarget.privateKey.addRevoker(revoker.publicKey, declarationDate);
      // the certificate embeds `otherTarget`, hence it cannot apply to `declaredKey`
      const foreignCertificate = await otherDeclared.getDesignatedRevocationCertificate(
        revoker.privateKey, {}, revocationDate, config
      );
      await expect(
        declaredKey.applyRevocationCertificate(foreignCertificate, revocationDate, config)
      ).to.be.rejectedWith('Revocation signature does not match key');
    });

    it('a received key block carrying the revocation signature cannot be used for encryption', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const receivedKey = declaredKey.clone();
      receivedKey.revocationSignatures.push(
        await createKeyRevocationSignature(declaredKey, revoker.privateKey.keyPacket, revocationDate, config)
      );
      // round-trip through the wire format, as if fetched from a key server
      const parsedKey = await openpgp.readKey({ binaryKey: receivedKey.toPublic().write(), config });

      const message = await openpgp.createMessage({ text: 'hello' });
      await expect(
        openpgp.encrypt({ message, encryptionKeys: parsedKey, config })
      ).to.be.rejectedWith(/Primary key is revoked/);
    });

    it('update() merges a revocation signature issued by the designated revoker', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const source = declaredKey.toPublic().clone();
      source.revocationSignatures.push(
        await createKeyRevocationSignature(declaredKey, revoker.privateKey.keyPacket, revocationDate, config)
      );
      const dest = declaredKey.toPublic();

      // with the revoker key, the merged key is considered revoked
      const updated = await dest.update(source, revocationDate, config);
      expect(updated.revocationSignatures).to.have.length(1);
      await expect(updated.verifyPrimaryKey(revocationDate, {}, config)).to.be.rejectedWith('Primary key is revoked');

      // without the revoker key, the signature is merged (if the destination has no revocation signature yet)
      // but it is not honoured, i.e. the key is still valid
      if (!dest.revocationSignatures.length) {
        const unconfiguredUpdated = await dest.update(source, revocationDate, { ...openpgp.config });
        expect(unconfiguredUpdated.revocationSignatures).to.have.length(1);
        expect(await unconfiguredUpdated.isRevoked(null, null, revocationDate, { ...openpgp.config })).to.equal(false);
        await unconfiguredUpdated.verifyPrimaryKey(revocationDate, {}, { ...openpgp.config });
      }
    });
  });

  describe('undeclared key', function() {
    it('a third-party revocation signature is ignored even if the revoker key is configured', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const receivedKey = target.privateKey.clone();
      receivedKey.revocationSignatures.push(
        await createKeyRevocationSignature(target.privateKey, revoker.privateKey.keyPacket, revocationDate, config)
      );
      expect(await receivedKey.isRevoked(null, null, revocationDate, config)).to.equal(false);
      await receivedKey.verifyPrimaryKey(revocationDate, {}, config);
      // the key is still usable for encryption
      await receivedKey.toPublic().getEncryptionKey(undefined, revocationDate, {}, config);
    });

    it('applyRevocationCertificate() rejects a third-party certificate', async function() {
      const config = { ...openpgp.config, designatedRevokers: [revoker.publicKey] };
      const revocationSignature = await createKeyRevocationSignature(
        target.privateKey, revoker.privateKey.keyPacket, revocationDate, config
      );
      const packetlist = new openpgp.PacketList();
      packetlist.push(revocationSignature);
      const revocationCertificate = openpgp.armor(openpgp.enums.armor.publicKey, packetlist.write());

      await expect(
        target.privateKey.applyRevocationCertificate(revocationCertificate, revocationDate, config)
      ).to.be.rejectedWith('Revocation signature does not match key');
    });
  });

  describe('declaration restrictions', function() {
    it('getDesignatedRevocationCertificate() rejects a key that is not a declared revoker', async function() {
      const declared = await target.privateKey.addRevoker(revoker.publicKey, declarationDate);
      await expect(
        declared.getDesignatedRevocationCertificate(outsider.privateKey, {}, revocationDate)
      ).to.be.rejectedWith(/not a designated revoker/);
    });

    it('addRevoker() rejects encrypted private keys', async function() {
      const encryptedKey = await openpgp.encryptKey({
        privateKey: (await generateTestKey('encrypted')).privateKey,
        passphrase: 'passphrase'
      });
      await expect(encryptedKey.addRevoker(revoker.publicKey, declarationDate))
        .to.be.rejectedWith('Signing key is not decrypted.');
    });

    it('a revocation key subpacket on a User ID self-signature is still rejected', async function() {
      // This matches the existing behaviour, see the `key_with_authorized_revocation_key` fixture in key.js
      const armoredKey = await openpgp.readKey({
        armoredKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

xsBNBFujnwwBCADK1xX03tSCmktPDS9Ncij3O5wG+F5/5Zm7QJDc39Wt1t/K
szCSobWtm/UObQVZjsTGwg0ZUPgepgWGGDBL0dlc1NObwUiOhGYnJnd4V25P
iU5Mg3+DhRq+LzNK+oGlpVPDpwQ48S8HOphbswKUpuaDcEQ2f+NKIc0eXe5m
ut5x9uoVj8jneUNsHYq6FIlxh4knzpJWFj5+LNi7plMCwKip6srVNf8He/q0
0xA/4vjSIOfGIE7TCBH33CbHEr98p81Cf4g0E+kswEz5iWE2SDCyYgQkMrkz
H9mtVqk3nFT8NR0USxKqH9bGhaTx1AWq/HDgsphayPEWQ0usjQDrbQUnABEB
AAHNDnRlc3QgPGFAYi5jb20+wsCNBBABCABBBQJbo58MBgsJBwgDAhcMgAH0
cOUNyxrV8eZOCGRKY2E6TW5AlAkQWICi/ReDcrkEFQgKAgMWAgECGQECGwMC
HgEAADgHB/0WIHh6maX2LZ0u5ujk1tZxWMrCycccopdQNKN0RGD98X4fyY6J
wfmKb107gcidJBFct0sVWFW8GU42w9pVMU5qWD6kyFkgcmov319UL+7aZ19b
HOWVKUTb6rFG8/qAbq3BF7YB/cZIBWMFKAS3BRJ4Kz23GheAB2A9oVLmuq5o
gW5c2R1YC0T0XyXEFiw9uZ+AS6kEZymFPRQfPUIbJs1ct/lAN+mC9Qp0Y6CL
60Hd6jlKUb6TgljaQ6CtLfT9v72GeKznapKr9IEtsgYv69j0c/MRM2nmu50c
g+fICiiHrTbNS6jkUz0pZLe7hdhWHeEiqcA9+GC1DxOQCRCS/YNfzsBNBFuj
nwwBCADK1xX03tSCmktPDS9Ncij3O5wG+F5/5Zm7QJDc39Wt1t/KszCSobWt
m/UObQVZjsTGwg0ZUPgepgWGGDBL0dlc1NObwUiOhGYnJnd4V25PiU5Mg3+D
hRq+LzNK+oGlpVPDpwQ48S8HOphbswKUpuaDcEQ2f+NKIc0eXe5mut5x9uoV
j8jneUNsHYq6FIlxh4knzpJWFj5+LNi7plMCwKip6srVNf8He/q00xA/4vjS
IOfGIE7TCBH33CbHEr98p81Cf4g0E+kswEz5iWE2SDCyYgQkMrkzH9mtVqk3
nFT8NR0USxKqH9bGhaTx1AWq/HDgsphayPEWQ0usjQDrbQUnABEBAAHCwF8E
GAEIABMFAlujnwwJEFiAov0Xg3K5AhsMAACI/QgArvTcutod+7n1D8wCwM50
jo3x4KPuQw+NwbOnMbFwv0R8i8NqtSFf2bYkkZ7RLViTmphvSon4h2WgfczL
SBulZ1QZF7zCKXmXDg8/HZgRUflC1XMixpB8Hqouin5AVgMbsbHg30V2uPco
V3DeFQ8HWxQC9symaMW/20MkqNXgCjM0us7kVwTEJQqZ6KYrFVjKyprSQRyP
rfckEBuZnj91OS+kAHlZ+ScZIuV4QVF0e2U6oEuB+qFXppR030PJoO6WDOzm
67hkzfrc3VpKw/I+vVJnZb4GOhNTSpa+p8i4gTyWmrOZ0G85QoldHWlWaRBg
lbjwPj3QUTbLFvHisYzXEQ==
=aT8U
-----END PGP PUBLIC KEY BLOCK-----
`
      });
      await expect(armoredKey.getPrimaryUser())
        .to.be.rejectedWith('This key is intended to be revoked with an authorized key, which OpenPGP.js does not support.');
    });
  });
});
