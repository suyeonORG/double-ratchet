/**
 * /src/ratchet/legacy.ts
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

import { DHRatchetStepEnhanced, DHRatchetStepStackEnhanced } from "./dh-step";

/**
 * Legacy DHRatchetStep class for backward compatibility.
 * @deprecated Use DHRatchetStepEnhanced instead
 */
export class DHRatchetStep extends DHRatchetStepEnhanced {}

/**
 * Legacy DHRatchetStepStack class for backward compatibility.
 * @deprecated Use DHRatchetStepStackEnhanced instead
 */
export class DHRatchetStepStack extends DHRatchetStepStackEnhanced {}
