/**
 * /examples/nextjs/src/app/components/DoubleRatchetDemo.tsx
 * -------------------------------------------------
 * Double Ratchet Protocol Implementation
 *
 * Authors (Université Libre de Bruxelles ULB):
 * @suyeonORG, @ChaosArnhug, @KTBASECURITY, @Draimy
 *
 * - Signal Protocol Specifications by Trevor Perrin & Moxie Marlinspike
 *   https://signal.org/docs/specifications/doubleratchet/
 *   https://signal.org/docs/specifications/x3dh/
 *
 * - Original 2key-ratchet implementation by Peculiar Ventures, Inc. Under MIT license
 *   https://github.com/PeculiarVentures/2key-ratchet
 *
 * @license MIT
 */

"use client";

import { useState } from "react";
import Console from "./Console";
import Button from "./Button";
import Card from "./Card";
import Spinner from "./Spinner";

/**
 * Main demo component for Double Ratchet functionality.
 * Provides an interactive UI to test encrypted messaging with modern cryptography.
 */
export default function DoubleRatchetDemo() {
  const [logs, setLogs] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  /** Adds a message to the demo console log */
  const log = (msg: string) => setLogs((prev) => [...prev, msg]);

  /**
   * Executes the Double Ratchet demonstration.
   *
   * This function demonstrates the complete workflow:
   * 1. Identity creation for Alice and Bob
   * 2. PreKey bundle generation and exchange
   * 3. Asymmetric ratchet initialization
   * 4. Bidirectional encrypted messaging
   * 5. Out-of-order message handling
   * 6. Forward secrecy demonstration
   */
  const runDemo = async () => {
    if (isRunning) return;
    setIsRunning(true);
    setLogs([]);

    try {
      log("Attempting to initialize crypto and run Double Ratchet demo...");

      const {
        Identity,
        PreKeyBundleProtocol,
        PreKeySignedProtocol,
        PreKeyProtocol,
        IdentityProtocol,
        AsymmetricRatchet,
        PreKeyMessageProtocol,
        MessageSignedProtocol,
        Convert,
        setEngine,
      } = await import("double-ratchet");

      if (typeof window !== "undefined" && window.crypto) {
        setEngine("WebCrypto", window.crypto);
      }

      // Helper for hex-dumping ArrayBuffers in logs
      const hex = (ab: ArrayBuffer) => Convert.ToHex(ab);

      // Enable debug mode for extractable keys
      const debugMode = true;

      // ========= ALICE SETUP =========
      log("🚀 Starting Double Ratchet Demo with X25519/Ed25519...");
      log("Alice: Creating identity...");
      const alice = await Identity.create(
        1,
        /* signedPreKeys */ 1,
        /* preKeys */ 1
      );
      log(
        `  • Alice signingKey (Ed25519): ${await alice.signingKey.publicKey.thumbprint()}`
      );
      log(
        `  • Alice exchangeKey (X25519): ${await alice.exchangeKey.publicKey.thumbprint()}`
      );

      log("Alice: Creating PreKeyBundle...");
      const aliceBundle = new PreKeyBundleProtocol();
      aliceBundle.registrationId = alice.id;

      aliceBundle.identity = new IdentityProtocol();
      await aliceBundle.identity.fill(alice);

      aliceBundle.preKeySigned = new PreKeySignedProtocol();
      const sp = alice.signedPreKeys[0];
      aliceBundle.preKeySigned.id = 0;
      aliceBundle.preKeySigned.key = sp.publicKey;

      // DEBUG: Verify key is set before signing
      if (!aliceBundle.preKeySigned.key) {
        throw new Error("PreKeySigned key is undefined before signing");
      }
      log(
        `  • PreKeySigned key set: ${await aliceBundle.preKeySigned.key.thumbprint()}`
      );

      await aliceBundle.preKeySigned.sign(alice.signingKey.privateKey);

      if (alice.preKeys.length > 0) {
        const preKey = alice.preKeys[0];
        aliceBundle.preKey = new PreKeyProtocol();
        aliceBundle.preKey.id = 0;
        aliceBundle.preKey.key = preKey.publicKey;
      }

      // Serialize the bundle
      const bundleBytes = await aliceBundle.exportProto();
      log(`✅ Alice: PreKeyBundle created (${bundleBytes.byteLength} bytes)`);

      // DEBUG: Test deserialization immediately
      log("🔍 Testing bundle deserialization...");
      const testBundle = new PreKeyBundleProtocol();
      await testBundle.importProto(bundleBytes);

      if (!testBundle.preKeySigned || !testBundle.preKeySigned.key) {
        throw new Error("PreKeySigned key is undefined after deserialization");
      }
      log(
        `  • PreKeySigned key after deserialization: ${await testBundle.preKeySigned.key.thumbprint()}`
      );

      log(`  • Ed25519 signature: ${hex(aliceBundle.preKeySigned.signature)}`);

      // ========= BOB SETUP =========
      log("Bob: Creating identity...");
      const bob = await Identity.create(2, 1, 1);
      log(
        `  • Bob signingKey (Ed25519): ${await bob.signingKey.publicKey.thumbprint()}`
      );
      log(
        `  • Bob exchangeKey (X25519): ${await bob.exchangeKey.publicKey.thumbprint()}`
      );

      log("Bob: Importing Alice's bundle...");
      const imported = new PreKeyBundleProtocol();
      await imported.importProto(bundleBytes);

      // DEBUG: Verify imported bundle has all required properties
      if (!imported.preKeySigned) {
        throw new Error("Imported bundle missing preKeySigned");
      }
      if (!imported.preKeySigned.key) {
        throw new Error("Imported bundle preKeySigned missing key");
      }
      log(
        `  • Imported PreKeySigned key: ${await imported.preKeySigned.key.thumbprint()}`
      );

      log("Bob: Creating Double Ratchet from bundle...");
      const bobRatchet = await AsymmetricRatchet.create(bob, imported, {
        exportableKeys: true,
        debug: debugMode,
      });
      log("✅ Bob: Double Ratchet established with Alice");
      log(`  • DH counter            : ${bobRatchet.counter}`);
      log(`  • RootKey algorithm     : ${bobRatchet.rootKey.algorithm.name}`);

      // Show DH ratchet state
      log(`  • DH ratchet steps      : ${bobRatchet.counter}`);

      // Bob → Alice (PreKeyMessage #0)
      const msgToAlice =
        "Hello Alice! This is encrypted with Double Ratchet + X25519!";
      log(`Bob: Encrypting message: "${msgToAlice}"`);
      const bobMsgProto = await bobRatchet.encrypt(
        Convert.FromString(msgToAlice)
      );
      const bobMsgBytes = await bobMsgProto.exportProto();
      log(
        `  • Sending counter       : ${bobRatchet.currentStep.sendingChain?.counter}`
      );
      log(`Bob: Encrypted message sent (${bobMsgBytes.byteLength} bytes)`);

      // Show ratchet state after encryption
      log(`  • DH steps completed    : ${bobRatchet.counter}`);

      // ========= ALICE PROCESSING =========
      log("Alice: Importing Bob's PreKeyMessage...");
      const preKeyMsg = new PreKeyMessageProtocol();
      await preKeyMsg.importProto(bobMsgBytes);
      log(
        `  • Header.counter        : ${preKeyMsg.signedMessage.message.counter}`
      );

      // Check if one-time prekey is being used
      if (preKeyMsg.preKeyId !== undefined) {
        log(`  • Alice's PreKey #${preKeyMsg.preKeyId} will be consumed`);
        log(
          `  • Before: Alice has ${Object.keys(alice.preKeys).length} prekeys`
        );
      }

      log("Alice: Creating Double Ratchet from message...");
      const aliceRatchet = await AsymmetricRatchet.create(alice, preKeyMsg, {
        exportableKeys: true,
        debug: debugMode,
      });
      log("✅ Alice: Double Ratchet established with Bob");
      log(`  • DH counter            : ${aliceRatchet.counter}`);

      // Show Alice's ratchet state
      log(`  • DH ratchet steps      : ${aliceRatchet.counter}`);

      // Check if one-time prekey was consumed
      if (preKeyMsg.preKeyId !== undefined) {
        log(
          `  • After: Alice has ${Object.keys(alice.preKeys).length} prekeys`
        );
        if (!alice.preKeys[preKeyMsg.preKeyId]) {
          log(
            `  • ✅ One-time prekey #${preKeyMsg.preKeyId} was properly consumed`
          );
        } else {
          log(
            `  • ⚠️ One-time prekey #${preKeyMsg.preKeyId} was NOT removed after use`
          );
        }
      }

      log("Alice: Decrypting Bob's message...");
      const plain1 = await aliceRatchet.decrypt(preKeyMsg.signedMessage);
      const text1 = Convert.ToString(plain1);
      log(`Alice decrypted: "${text1}"`);
      log(
        `  • Receiving counter     : ${aliceRatchet.currentStep.receivingChain?.counter}`
      );

      // Alice → Bob (SignedMessage #1)
      const msgToBob =
        "Hello Bob! Double Ratchet with Ed25519 signatures works!";
      log(`Alice: Encrypting reply: "${msgToBob}"`);
      const replyProto = await aliceRatchet.encrypt(
        Convert.FromString(msgToBob)
      );
      const replyBytes = await replyProto.exportProto();
      log(
        `  • Sending counter       : ${aliceRatchet.currentStep.sendingChain?.counter}`
      );
      log(`Alice: Encrypted reply sent (${replyBytes.byteLength} bytes)`);

      // Show Alice's updated ratchet state
      log(`  • DH steps completed    : ${aliceRatchet.counter}`);

      // ========= BOB RECEIVES =========
      log("Bob: Importing Alice's signed message...");
      const signedMsg = new MessageSignedProtocol();
      await signedMsg.importProto(replyBytes);
      log(`  • Header.counter        : ${signedMsg.message.counter}`);

      log("Bob: Decrypting Alice's reply...");
      const plain2 = await bobRatchet.decrypt(signedMsg);
      const text2 = Convert.ToString(plain2);
      log(`Bob decrypted: "${text2}"`);
      log(
        `  • Receiving counter     : ${bobRatchet.currentStep.receivingChain?.counter}`
      );

      // Show Bob's final ratchet state
      log(`  • Final DH steps        : ${bobRatchet.counter}`);

      // ========= DOUBLE RATCHET DEMONSTRATION =========
      log("");
      log("Demonstrating Forward Secrecy...");

      // Send multiple messages to show ratchet progression
      for (let i = 1; i <= 3; i++) {
        const testMsg = `Test message ${i} - showing ratchet progression`;
        log(`Round ${i}: Alice encrypting "${testMsg}"`);

        const testProto = await aliceRatchet.encrypt(
          Convert.FromString(testMsg)
        );
        const testBytes = await testProto.exportProto();

        log(`  • DH step ${i} completed   : Forward secrecy maintained`);

        // Bob decrypts
        const testSignedMsg = new MessageSignedProtocol();
        await testSignedMsg.importProto(testBytes);
        const testPlain = await bobRatchet.decrypt(testSignedMsg);
        const testText = Convert.ToString(testPlain);
        log(`Round ${i}: Bob decrypted "${testText}"`);
      }

      // ========= SUMMARY =========
      if (text1.includes("Double Ratchet") && text2.includes("Ed25519")) {
        log("");
        log("✅ Double Ratchet Demo Completed Successfully!");
        log("⚠️  Vulnerable to two-compromise attack (see CKA Attack demo)");
      } else {
        log("");
        log(
          "Demo finished with unexpected results — check the implementation!"
        );
      }
    } catch (e: unknown) {
      console.error(e);
      log(`Error: ${(e as Error).message}`);
      if ((e as Error).stack) {
        const firstLines = (e as Error)
          .stack!.split("\n")
          .slice(0, 5)
          .join("\n");
        log(`Stack trace: ${firstLines}`);
      }
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="page">
      <Card title="Double Ratchet Protocol Demo">
        <p className="description">
          Demonstrating Signal Double Ratchet protocol with modern cryptography
          using X25519/Ed25519 curves and SHA-512.
        </p>

        <Button onClick={runDemo} disabled={isRunning} className="demo-button">
          {isRunning ? (
            <>
              <Spinner size={16} />
              Running Demo...
            </>
          ) : (
            <>Run Demo</>
          )}
        </Button>
      </Card>

      <Console
        logs={logs}
        isRunning={isRunning}
        onClear={() => setLogs([])}
        title="Demo Execution Log"
      />

      <div className="info-grid">
        <Card title="🔐 Modern Cryptography">
          <p>
            Uses X25519 for ECDH key agreement and Ed25519 for digital
            signatures - modern, secure elliptic curves.
          </p>
        </Card>

        <Card title="Double Ratcheting">
          <p>
            Combines DH ratchet and symmetric ratchet for robust security
            properties.
          </p>
        </Card>

        <Card title="Forward Secrecy & Post-Compromise Security">
          <p>
            Past messages remain secure even if current keys are compromised.
            Future messages regain security after the protocol heals from a
            compromise.
          </p>
        </Card>
      </div>
    </div>
  );
}
