/**
 * /examples/nextjs/src/app/components/Spinner.tsx
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
interface SpinnerProps {
  size?: number;
  className?: string;
}

export default function Spinner({ size = 20, className = "" }: SpinnerProps) {
  return (
    <div
      className={`spinner ${className}`}
      style={{ width: size, height: size }}
    >
      <div className="spinner-circle"></div>
    </div>
  );
}
