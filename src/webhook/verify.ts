import { createHmac, timingSafeEqual } from 'crypto'
import { WebhookEvent } from '../types'
import { SipHeronError, ValidationError } from '../errors'

export interface WebhookVerifyOptions {
  payload: string | Buffer
  signature: string
  secret: string
  tolerance?: number
}

export interface WebhookParseOptions {
  body: string
  signature: string
  secret: string
}

/**
 * Verify a SipHeron webhook signature exactly.
 * Uses constant-time equality to prevent timing attacks.
 */
export function verifyWebhookSignature({
  payload,
  signature,
  secret,
  tolerance = 300 // 5 minutes default tolerance
}: WebhookVerifyOptions): boolean {
  if (!payload || !signature || !secret) {
    return false
  }

  try {
    const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf-8')
    const computedSignature = createHmac('sha256', secret)
      .update(payloadBuffer)
      .digest('hex')

    // Optional: if signatures in SipHeron use timestamps (e.g. `t=123,v1=abc`),
    // you would parse that here. For now, assuming direct HMAC hex.
    const sigBuffer = Buffer.from(signature, 'utf8')
    const computedBuffer = Buffer.from(computedSignature, 'utf8')

    if (sigBuffer.length !== computedBuffer.length) {
      return false
    }

    return timingSafeEqual(sigBuffer, computedBuffer)
  } catch (err) {
    return false
  }
}

/**
 * Parses and verifies a webhook payload in one step.
 */
export function parseWebhookEvent({
  body,
  signature,
  secret
}: WebhookParseOptions): WebhookEvent {
  const isValid = verifyWebhookSignature({
    payload: body,
    signature,
    secret
  })

  if (!isValid) {
    throw new SipHeronError('Invalid webhook signature', 'WEBHOOK_SIGNATURE_INVALID', 401)
  }

  try {
    return JSON.parse(body) as WebhookEvent
  } catch (err) {
    throw new ValidationError('Webhook payload is not valid JSON')
  }
}
