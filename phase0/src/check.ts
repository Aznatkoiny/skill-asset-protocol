import { WIP_TOKEN_ADDRESS } from "@story-protocol/core-sdk";
import { formatEther } from "viem";

import {
  AENEID_CHAIN_ID,
  DEMO_ROOT_MINTING_FEE,
  missingOperationStages,
  type DemoChain,
} from "./demo";
import { estimateRemainingDemoGasMinimum } from "./funding";
import {
  parseRegistrationManifest,
  type RegistrationStore,
} from "./registrations";
import type { OperationJournal } from "./transactions";

export type CheckChain = Pick<
  DemoChain,
  "getChainId" | "getBalance" | "getGasPrice" | "getDerivativeFeeReadiness"
>;

export interface CheckReport {
  wallet: `0x${string}`;
  chain: string;
  pendingRecovery: string;
  remainingNewWrites: number;
  nativeIpBalance: string;
  gasPrice: string;
  estimatedGasMinimum: string;
  nativeGasReady: "yes" | "no" | "deferred until exact-hash recovery";
  derivativeFeeToken: string;
  configuredFeeEstimate: string;
  wipBalance: string;
  wipAllowance: string;
  derivativeWorkflowsSpender: string;
  nextDerivativeWipReady: string;
}

export interface BuildCheckReportInput {
  wallet: `0x${string}`;
  chain: CheckChain;
  store: RegistrationStore;
  journal: OperationJournal;
}

const DEFERRED = "deferred until exact-hash recovery";
const NOT_APPLICABLE = "not applicable until the next new Derivative";
const NOT_READ = "not read (no remaining new writes)";
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function requireReadinessShape(value: Awaited<ReturnType<CheckChain["getDerivativeFeeReadiness"]>>) {
  if (!sameAddress(value.currencyToken, WIP_TOKEN_ADDRESS)) {
    throw new Error(`Derivative readiness returned unsupported token ${value.currencyToken}`);
  }
  if (value.requiredAmount !== DEMO_ROOT_MINTING_FEE) {
    throw new Error("Derivative readiness returned a different configured fee amount");
  }
  if (!ADDRESS.test(value.spender) || /^0x0{40}$/i.test(value.spender)) {
    throw new Error("Derivative readiness returned a malformed workflows spender");
  }
  if (value.balance < 0n || value.allowance < 0n) {
    throw new Error("Derivative readiness returned a negative WIP balance or allowance");
  }
}

export async function buildCheckReport(input: BuildCheckReportInput): Promise<CheckReport> {
  return input.journal.withExclusiveLease(async (journal) => {
    const snapshot = await journal.load();
    const manifest = parseRegistrationManifest(await input.store.load());
    const remainingStages = missingOperationStages(manifest);
    const remainingNewWrites = remainingStages.length;

    if (snapshot.operation) {
      return {
        wallet: snapshot.operation.intent.wallet,
        chain: `Story Aeneid (${AENEID_CHAIN_ID}) — deferred until exact-hash recovery`,
        pendingRecovery: `required (${snapshot.operation.stage}, ${snapshot.operation.transactionHash})`,
        remainingNewWrites,
        nativeIpBalance: DEFERRED,
        gasPrice: DEFERRED,
        estimatedGasMinimum: DEFERRED,
        nativeGasReady: DEFERRED,
        derivativeFeeToken: DEFERRED,
        configuredFeeEstimate: "0.001 WIP per Derivative",
        wipBalance: DEFERRED,
        wipAllowance: DEFERRED,
        derivativeWorkflowsSpender: DEFERRED,
        nextDerivativeWipReady: DEFERRED,
      };
    }

    if (manifest.wallet && !sameAddress(manifest.wallet, input.wallet)) {
      throw new Error(`Existing registration evidence belongs to another wallet: ${manifest.wallet}`);
    }
    const chainId = await input.chain.getChainId();
    if (chainId !== AENEID_CHAIN_ID) {
      throw new Error(`Phase 0 requires Story Aeneid chain ${AENEID_CHAIN_ID}; received ${chainId}`);
    }

    let nativeIpBalance = NOT_READ;
    let gasPrice = NOT_READ;
    let estimatedGasMinimum = "0 IP";
    let nativeGasReady: CheckReport["nativeGasReady"] = "yes";
    if (remainingNewWrites > 0) {
      const [balance, currentGasPrice] = await Promise.all([
        input.chain.getBalance(input.wallet),
        input.chain.getGasPrice(),
      ]);
      const minimum = estimateRemainingDemoGasMinimum({
        gasPrice: currentGasPrice,
        remainingNewWrites,
      });
      nativeIpBalance = `${formatEther(balance)} IP`;
      gasPrice = `${currentGasPrice} wei/gas`;
      estimatedGasMinimum = `${formatEther(minimum)} IP`;
      nativeGasReady = balance >= minimum ? "yes" : "no";
    }

    let derivativeFeeToken = NOT_APPLICABLE;
    let wipBalance = NOT_APPLICABLE;
    let wipAllowance = NOT_APPLICABLE;
    let derivativeWorkflowsSpender = NOT_APPLICABLE;
    let nextDerivativeWipReady = NOT_APPLICABLE;
    const nextStage = remainingStages[0];
    if (nextStage === "child" || nextStage === "grandchild") {
      const readiness = await input.chain.getDerivativeFeeReadiness({
        wallet: input.wallet,
        currencyToken: WIP_TOKEN_ADDRESS,
        requiredAmount: DEMO_ROOT_MINTING_FEE,
      });
      requireReadinessShape(readiness);
      derivativeFeeToken = readiness.currencyToken;
      wipBalance = `${formatEther(readiness.balance)} WIP`;
      wipAllowance = `${formatEther(readiness.allowance)} WIP`;
      derivativeWorkflowsSpender = readiness.spender;
      nextDerivativeWipReady = readiness.balance >= readiness.requiredAmount
        && readiness.allowance >= readiness.requiredAmount
        ? "yes"
        : "no";
    }

    return {
      wallet: input.wallet,
      chain: `Story Aeneid (${chainId})`,
      pendingRecovery: "none",
      remainingNewWrites,
      nativeIpBalance,
      gasPrice,
      estimatedGasMinimum,
      nativeGasReady,
      derivativeFeeToken,
      configuredFeeEstimate: "0.001 WIP per Derivative",
      wipBalance,
      wipAllowance,
      derivativeWorkflowsSpender,
      nextDerivativeWipReady,
    };
  });
}

export function renderCheckReport(report: CheckReport): string[] {
  return [
    `wallet                       : ${report.wallet}`,
    `chain                        : ${report.chain}`,
    `pending recovery             : ${report.pendingRecovery}`,
    `remaining new writes         : ${report.remainingNewWrites}`,
    `native IP balance            : ${report.nativeIpBalance}`,
    `gas price                    : ${report.gasPrice}`,
    `estimated gas minimum        : ${report.estimatedGasMinimum}`,
    `native gas ready             : ${report.nativeGasReady}`,
    `Derivative fee token         : ${report.derivativeFeeToken}`,
    `configured fee estimate      : ${report.configuredFeeEstimate}`,
    `WIP balance                  : ${report.wipBalance}`,
    `WIP allowance                : ${report.wipAllowance}`,
    `DerivativeWorkflows spender  : ${report.derivativeWorkflowsSpender}`,
    `next Derivative WIP ready    : ${report.nextDerivativeWipReady}`,
  ];
}
