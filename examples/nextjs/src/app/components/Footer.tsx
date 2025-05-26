/**
 * /examples/nextjs/src/app/components/Footer.tsx
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
export default function Footer() {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-section">
          <h4>Double Ratchet Demo</h4>
          <p>Version 1.0.0</p>
        </div>
        
        <div className="footer-section">
          <h4>Implementation</h4>
          <p>Signal Protocol Specification</p>
          <p>X25519, Ed25519, AES-GCM, SHA-512</p>
        </div>
        
        <div className="footer-section">
          <h4>Academic Team</h4>
          <p>Université Libre de Bruxelles (ULB)</p>
          <p>UCLouvain • Unamur</p>
        </div>
        
        <div className="footer-section">
          <h4>Security Notice</h4>
          <p>This implementation demonstrates the theoretical</p>
          <p>two-compromise attack vulnerability (CKA demo)</p>
        </div>
      </div>
      
      <div className="footer-bottom">
        <p>&copy; {currentYear} Double Ratchet Implementation. Built with TypeScript and modern cryptography.</p>
        <p>MIT License • Based on Signal Protocol specification</p>
      </div>
    </footer>
  );
}