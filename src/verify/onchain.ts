import { Connection, PublicKey } from '@solana/web3.js'
import * as anchor from '@coral-xyz/anchor'
import { SIPHERON_PROGRAM_ID, SOLANA_NETWORKS } from '../anchor/solana'
import idl from '../anchor/idl.json'
import { hashDocument } from '../hash'
import { ValidationError, SolanaConnectionError } from '../errors'

export interface OnChainVerificationOptions {
  hash?: string
  buffer?: Buffer
  network: 'devnet' | 'mainnet'
  rpcUrl?: string
  ownerPublicKey?: PublicKey | string
}

export interface OnChainVerificationResult {
  authentic: boolean
  hash: string
  pda?: string
  owner?: string
  timestamp?: number
  isRevoked?: boolean
  metadata?: string
}

/**
 * Derive the Program Derived Address (PDA) for any anchor record.
 */
export function deriveAnchorAddress(
  hashString: string,
  ownerPublicKey: PublicKey,
  network: 'devnet' | 'mainnet'
): PublicKey {
  const hashBuffer = Buffer.from(hashString, 'hex')
  const programId = SIPHERON_PROGRAM_ID[network]

  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from('hash_record'), hashBuffer, ownerPublicKey.toBuffer()],
    programId
  )
  return pda
}

/**
 * Verify an anchor record directly by reading the Solana blockchain.
 * Does not require a SipHeron API key or server connection.
 */
export async function verifyOnChain(options: OnChainVerificationOptions): Promise<OnChainVerificationResult> {
  const { network, rpcUrl, ownerPublicKey } = options

  if (!options.hash && !options.buffer) {
    throw new ValidationError('Must provide either a hash or file buffer')
  }

  if (!ownerPublicKey) {
    throw new ValidationError('ownerPublicKey is required for direct on-chain verification in v1 layout')
  }

  const hashString = options.buffer 
    ? await hashDocument(options.buffer) 
    : options.hash!.toLowerCase()

  const connectionUrl = rpcUrl || SOLANA_NETWORKS[network]
  const connection = new Connection(connectionUrl, 'confirmed')

  const ownerPk = typeof ownerPublicKey === 'string' 
    ? new PublicKey(ownerPublicKey) 
    : ownerPublicKey

  const pda = deriveAnchorAddress(hashString, ownerPk, network)

  const programId = SIPHERON_PROGRAM_ID[network]
  const provider = new anchor.AnchorProvider(
    connection,
    new anchor.Wallet(Keypair.generate()), // Dummy wallet for read-only
    {}
  )
  const program = new anchor.Program(idl as anchor.Idl, provider) as any

  try {
    const record = await program.account.hashRecord.fetch(pda)

    return {
      authentic: !record.isRevoked,
      hash: hashString,
      pda: pda.toBase58(),
      owner: (record.owner as PublicKey).toBase58(),
      timestamp: (record.timestamp as anchor.BN).toNumber(),
      isRevoked: record.isRevoked as boolean,
      metadata: record.metadata as string,
    }
  } catch (err: any) {
    if (err.message && err.message.includes('Account does not exist')) {
       return {
         authentic: false,
         hash: hashString,
       }
    }
    throw new SolanaConnectionError(`Failed to verify on chain: ${err.message}`)
  }
}

// Dummy import for Keypair inside read-only wallet above
import { Keypair } from '@solana/web3.js'
