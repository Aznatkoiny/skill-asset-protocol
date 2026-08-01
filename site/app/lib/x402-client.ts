// x402-client.ts — the BUYER half of the x402 v1 protocol, in the browser.
//
// Mirrors the handshake of the working seller reference at
// spikes/pi-wielder/src/x402-seller.mjs:
//
//   1. fetch(url) → seller responds 402 with { x402Version: 1, accepts: [PaymentRequirements] }
//   2. Buyer takes accepts[0] (x402 v1 "exact" scheme on base-sepolia), builds an
//      EIP-3009 TransferWithAuthorization EIP-712 payload against Base Sepolia USDC,
//      and signs it with the connected wallet via eth_signTypedData_v4.
//      Signing is an off-chain authorization — the buyer never broadcasts a tx and
//      pays no gas; the facilitator settles transferWithAuthorization on-chain.
//   3. Buyer retries ONCE with X-PAYMENT: base64(JSON payment payload).
//   4. On success the seller sets X-PAYMENT-RESPONSE: base64({ success, transaction, ... })
//      — the settled txHash is the receipt.
//
// No wallet libraries, no deps — raw window.ethereum (EIP-1193) plus hand-rolled
// hex / base64 helpers.

// --- x402 v1 / Base Sepolia constants (mirror x402-seller.mjs) ---------------
export const X402_VERSION = 1;
export const NETWORK = 'base-sepolia';
export const CHAIN_ID = 84532;
export const CHAIN_ID_HEX = '0x14a34';
// Circle's canonical USDC deployment on Base Sepolia (6 decimals).
export const USDC_ADDRESS = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
// EIP-712 domain values USDC uses for EIP-3009 signatures.
export const USDC_EIP712 = { name: 'USDC', version: '2' };
export const USDC_DECIMALS = 6;

// --- wallet provider discovery (EIP-6963 + window.ethereum fallback) ----------
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
  }
}

// Multiple extensions race to own window.ethereum (Phantom, Coinbase, ...) and
// the winner may not implement the EVM methods this page needs. EIP-6963 lets
// every installed wallet announce itself instead; prefer MetaMask, then any
// announced wallet, then legacy window.ethereum.
interface AnnouncedProvider {
  info?: { rdns?: string; name?: string };
  provider: Eip1193Provider;
}

const announced: AnnouncedProvider[] = [];
if (typeof window !== 'undefined') {
  window.addEventListener('eip6963:announceProvider', (event) => {
    const detail = (event as CustomEvent<AnnouncedProvider>).detail;
    if (detail?.provider && !announced.some((p) => p.info?.rdns === detail.info?.rdns)) {
      announced.push(detail);
    }
  });
  window.dispatchEvent(new Event('eip6963:requestProvider'));
}

export const hasWallet = (): boolean =>
  typeof window !== 'undefined' && (announced.length > 0 || !!window.ethereum);

// PaymentRequirements as emitted by the seller's 402 body (accepts[0]).
export interface PaymentRequirements {
  scheme: string; // 'exact'
  network: string; // 'base-sepolia'
  maxAmountRequired: string; // atomic USDC (6 decimals), e.g. '250000'
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string; // USDC contract address
  extra?: { name?: string; version?: string };
}

export interface PaidReceipt {
  amountUSDC: number;
  txHash: string;
}

// --- hand-rolled helpers (no deps) --------------------------------------------
const bytesToHex = (bytes: Uint8Array): string =>
  '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const randomBytes32Hex = (): string => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
};

// UTF-8-safe base64 (btoa alone chokes on multi-byte chars).
const jsonToB64 = (obj: unknown): string => {
  const utf8 = new TextEncoder().encode(JSON.stringify(obj));
  let binary = '';
  for (let i = 0; i < utf8.length; i += 0x8000) {
    binary += String.fromCharCode(...utf8.subarray(i, i + 0x8000));
  }
  return btoa(binary);
};

const b64ToJson = <T>(s: string): T => {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
};

const getProvider = (): Eip1193Provider => {
  const metamask = announced.find((p) => p.info?.rdns === 'io.metamask');
  const provider =
    metamask?.provider ??
    announced[0]?.provider ??
    (typeof window !== 'undefined' ? window.ethereum : undefined);
  if (!provider) {
    throw new Error('No EIP-1193 wallet found — install MetaMask (or any injected wallet) to pay.');
  }
  return provider;
};

// --- ensureBaseSepolia ---------------------------------------------------------
// Get the wallet onto Base Sepolia (0x14a34) without assuming any particular
// wallet: skip if already there, try wallet_switchEthereumChain, fall back to
// wallet_addEthereumChain (some wallets reject the switch method outright, not
// just with 4902), and if it still won't move, say exactly what to do by hand.
export async function ensureBaseSepolia(provider: Eip1193Provider): Promise<void> {
  const chainId = async (): Promise<string | null> => {
    try {
      const id = await provider.request({ method: 'eth_chainId' });
      return typeof id === 'string' ? id.toLowerCase() : null;
    } catch {
      return null;
    }
  };

  if ((await chainId()) === CHAIN_ID_HEX) return;

  let switchErr: unknown = null;
  try {
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: CHAIN_ID_HEX }],
    });
  } catch (err) {
    switchErr = err;
  }
  if ((await chainId()) === CHAIN_ID_HEX) return;

  // 4001 = the user rejected the switch in the wallet UI; adding the chain
  // would just pop a second dialog at someone who said no.
  if ((switchErr as { code?: number })?.code === 4001) {
    throw new Error('Network switch rejected in the wallet — approve it and click INVOKE again.');
  }

  try {
    await provider.request({
      method: 'wallet_addEthereumChain',
      params: [
        {
          chainId: CHAIN_ID_HEX,
          chainName: 'Base Sepolia',
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
          rpcUrls: ['https://sepolia.base.org'],
          blockExplorerUrls: ['https://sepolia.basescan.org'],
        },
      ],
    });
  } catch {
    // Fall through to the final check and manual instruction.
  }
  if ((await chainId()) === CHAIN_ID_HEX) return;

  throw new Error(
    'Could not switch networks automatically. In your wallet, add or select "Base Sepolia" (chain 84532, RPC https://sepolia.base.org), then click INVOKE again.',
  );
}

// --- connectWallet ---------------------------------------------------------------
// Connect FIRST, then do chain operations: several wallets refuse chain
// requests coming from a not-yet-connected site.
export interface WalletSession {
  provider: Eip1193Provider;
  account: string;
}

export async function connectWallet(): Promise<WalletSession> {
  const provider = getProvider();
  const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as string[];
  const account = accounts?.[0];
  if (!account) throw new Error('Wallet returned no accounts.');
  await ensureBaseSepolia(provider);
  return { provider, account };
}

// --- EIP-3009 TransferWithAuthorization signing --------------------------------
async function signPayment(
  requirements: PaymentRequirements,
  session?: WalletSession,
): Promise<{ header: string; from: string }> {
  const { provider, account: from } = session ?? (await connectWallet());

  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from,
    to: requirements.payTo,
    value: requirements.maxAmountRequired, // atomic USDC, uint256 as decimal string
    validAfter: '0',
    validBefore: String(now + (requirements.maxTimeoutSeconds ?? 60) + 60),
    // Random 32-byte nonce — EIP-3009 nonces are single-use ON-CHAIN, which is
    // the protocol's replay protection: a replayed authorization fails /settle.
    nonce: randomBytes32Hex(),
  };

  // The seller publishes the EIP-712 domain values in requirements.extra.
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      TransferWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' },
      ],
    },
    primaryType: 'TransferWithAuthorization',
    domain: {
      name: requirements.extra?.name ?? USDC_EIP712.name,
      version: requirements.extra?.version ?? USDC_EIP712.version,
      chainId: CHAIN_ID,
      verifyingContract: requirements.asset ?? USDC_ADDRESS,
    },
    message: authorization,
  };

  const signature = (await provider.request({
    method: 'eth_signTypedData_v4',
    params: [from, JSON.stringify(typedData)],
  })) as string;

  // The X-PAYMENT envelope the seller (and the x402.org facilitator) expect:
  // base64(JSON payment payload), x402 v1 'exact' scheme.
  const paymentPayload = {
    x402Version: X402_VERSION,
    scheme: 'exact',
    network: NETWORK,
    payload: { signature, authorization },
  };

  return { header: jsonToB64(paymentPayload), from };
}

// --- payAndFetch ----------------------------------------------------------------
// fetch → if 402, parse accepts[0], sign EIP-3009 authorization, retry ONCE with
// the X-PAYMENT header. Returns the final response plus the settlement receipt
// (parsed from the standard X-PAYMENT-RESPONSE header) when a payment was made.
export async function payAndFetch(
  url: string,
  init?: RequestInit,
  session?: WalletSession,
): Promise<{ response: Response; paid?: PaidReceipt }> {
  const first = await fetch(url, init);
  if (first.status !== 402) {
    return { response: first };
  }

  // -- parse the 402 challenge --------------------------------------------------
  let challenge: { x402Version?: number; accepts?: PaymentRequirements[] };
  try {
    challenge = await first.json();
  } catch {
    throw new Error('Got 402 but the challenge body was not JSON.');
  }
  const requirements = challenge.accepts?.[0];
  if (!requirements) throw new Error('402 challenge carried no accepts[] payment requirements.');
  if (requirements.scheme !== 'exact' || requirements.network !== NETWORK) {
    throw new Error(
      `Unsupported payment requirements: scheme=${requirements.scheme} network=${requirements.network}`,
    );
  }

  // -- sign and retry once --------------------------------------------------------
  const { header } = await signPayment(requirements, session);
  const headers = new Headers(init?.headers);
  headers.set('X-PAYMENT', header);
  const response = await fetch(url, { ...init, headers });

  // -- read the settlement receipt -------------------------------------------------
  let paid: PaidReceipt | undefined;
  const receiptHeader = response.headers.get('X-PAYMENT-RESPONSE');
  if (receiptHeader) {
    try {
      const receipt = b64ToJson<{ success?: boolean; transaction?: string }>(receiptHeader);
      if (receipt.transaction) {
        paid = {
          amountUSDC: Number(requirements.maxAmountRequired) / 10 ** USDC_DECIMALS,
          txHash: receipt.transaction,
        };
      }
    } catch {
      // Malformed receipt header — the JSON body still carries `paid` on success.
    }
  }

  return { response, paid };
}
