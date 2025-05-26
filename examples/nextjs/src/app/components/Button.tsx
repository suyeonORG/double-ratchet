/**
 * /examples/nextjs/src/app/components/Button.tsx
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
import { ReactNode } from "react";

interface ButtonProps {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary" | "success" | "danger";
  className?: string;
}

export default function Button({
  children,
  onClick,
  disabled = false,
  variant = "primary",
  className = "",
}: ButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`btn btn-${variant} ${className}`}
    >
      {children}
    </button>
  );
}
