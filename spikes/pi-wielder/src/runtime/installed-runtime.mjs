import path from 'node:path';
import { types as utilTypes } from 'node:util';

import { startControlPlane } from '../control-plane.mjs';
import { loadControlPlaneConfig } from '../config.mjs';
import { acquireAuthorityLock } from '../kernel/authority-lock.mjs';
import { KernelError } from '../kernel/canonical.mjs';
import { assertRuntimeDeploymentBindings } from '../kernel/deployment.mjs';
import { recoverKernelAuthority } from '../kernel/recovery.mjs';
import { openRuntimeAuthority } from './authority.mjs';
import { listenActivatedConsole, listenLoopback, listenUnixAdmin } from './listeners.mjs';
import { assertKernelProcessIdentity, loadDeliveredEnvironment } from './secret-delivery.mjs';

async function productionExternalClients(environment) {
  const [{ CdpClient }, {createPublicClient, http}, {baseSepolia}] = await Promise.all([
    import('@coinbase/cdp-sdk'), import('viem'), import('viem/chains'),
  ]);
  return Object.freeze({
    cdpClient: new CdpClient({apiKeyId: environment.CDP_API_KEY_ID,
      apiKeySecret: environment.CDP_API_KEY_SECRET, walletSecret: environment.CDP_WALLET_SECRET}),
    publicClient: createPublicClient({chain: baseSepolia,
      transport: http(environment.WALLET_KERNEL_BASE_SEPOLIA_RPC_URL, {
        timeout: 5_000, retryCount: 0,
        fetchOptions: {redirect: 'error', credentials: 'omit', cache: 'no-store'},
      })}),
    fetchImpl: fetch,
  });
}

function capture(value, allowed, required) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).some(key => typeof key !== 'string' || !allowed.includes(key))
      || required.some(key => !Object.hasOwn(value, key))) throw new TypeError('Runtime composition shape is invalid');
  const result = {};
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Runtime composition is not inert');
    result[key] = descriptor.value;
  }
  return result;
}

/** Callable only by the verified, unprivileged service bootstrap; the live launch gate remains separate. */
export async function startInstalledControlPlane(input, external = {}) {
  const options = capture(input, [
    'environmentFilePath', 'credentialFilePath', 'kernelUid', 'kernelGid', 'release',
    'assertLiveAdmission', 'consoleActivation', 'publishReady', 'deployment',
  ], ['environmentFilePath', 'kernelUid', 'kernelGid', 'release', 'assertLiveAdmission', 'consoleActivation']);
  const injected = capture(external, ['externalClients'], []);
  assertKernelProcessIdentity(options);
  if (typeof options.assertLiveAdmission !== 'function'
      || (options.publishReady !== undefined && typeof options.publishReady !== 'function')) {
    throw new TypeError('Runtime admission and readiness hooks are invalid');
  }
  const environment = loadDeliveredEnvironment(options);
  let composition;
  try {
    const clients = injected.externalClients ?? await productionExternalClients(environment);
    return await startControlPlane({env: environment, dependencies: {
      checkoutRoot: path.resolve(environment.WALLET_KERNEL_RELEASE_ROOT),
      verifyRelease: async () => options.release,
      loadConfig: (request) => {
        const loaded = loadControlPlaneConfig({...request,
          verifiedReleaseRoot: environment.WALLET_KERNEL_RELEASE_ROOT});
        if (options.deployment) assertRuntimeDeploymentBindings(options.deployment, loaded.publicConfig);
        return loaded;
      },
      acquireAuthorityLock({config, role}) {
        return acquireAuthorityLock({databasePath: config.databasePath, role,
          pathTrust: Object.freeze({mode: config.mode, trustedAncestor: config.trustedAncestor,
            kernelUid: options.kernelUid, agentUid: config.expectedAgentUid})});
      },
      openAuthority({config, routes}) {
        composition = openRuntimeAuthority({config, routes, clients,
          pathTrust: Object.freeze({mode: config.mode, trustedAncestor: config.trustedAncestor,
            kernelUid: options.kernelUid, agentUid: config.expectedAgentUid})});
        return composition.authority;
      },
      recoverAuthority: (dependencies) => recoverKernelAuthority(dependencies),
      async assertLiveAdmission(context) {
        const admission = await options.assertLiveAdmission(context);
        if (admission?.isolation !== 'verified') {
          throw new KernelError('AGENT_IDENTITY_NOT_ISOLATED', 'Installed Agent isolation is not verified');
        }
        composition.assertIsolation(admission, context);
        await composition.assertObservation();
        return Object.freeze({isolation: 'verified', observer: 'verified'});
      },
      listenOperatorAdmin: (request) => listenUnixAdmin({...request,
        kernelUid: options.kernelUid, kernelGid: options.kernelGid}),
      listenOperatorConsole: (request) => listenActivatedConsole({...request,
        activation: options.consoleActivation}),
      listenAgent: listenLoopback,
      ...(options.publishReady ? {publishReady: options.publishReady} : {}),
    }});
  } catch (error) {
    // Provider errors can contain credential-bearing URLs. Expose codes only;
    // never retain their raw message/cause in bootstrap diagnostics.
    const code = error instanceof KernelError && /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.code)
      ? error.code : 'RUNTIME_STARTUP_FAILED';
    throw new KernelError(code, 'Installed Wallet Kernel startup failed');
  }
}
