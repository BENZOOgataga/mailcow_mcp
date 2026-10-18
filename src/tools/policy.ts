/**
 * Tool Exposure Policy
 *
 * Decides which tools a given deployment is allowed to register.
 *
 * The policy exists because this server can be reached in two very different
 * ways. Over stdio it is a local process launched by a desktop client, and the
 * only caller is the user. Over Streamable HTTP it is a network service that an
 * LLM vendor's infrastructure connects to, and the model driving it may have
 * read attacker-authored content — an email body, a queued message, a log line.
 *
 * A tool that destroys mail is therefore not the same risk in those two
 * deployments, and the policy is what distinguishes them.
 *
 * Tools are filtered at *registration* time rather than refused at call time.
 * A tool that is not registered does not appear in `tools/list`, so a model
 * cannot see that it exists, cannot be persuaded to call it, and cannot report
 * to a user that it was blocked. Refusing at call time leaks the surface.
 */

/**
 * Tools that permanently destroy data, or that break mail flow in a way the
 * estate will not notice until deliverability degrades.
 *
 * `update_dkim_key` is in this list and that is deliberate. Rotating a DKIM key
 * does not look destructive — nothing is deleted and the panel reports success —
 * but signing breaks the moment the key changes and stays broken until DNS
 * propagates. Mail keeps flowing while receivers start failing DMARC, and no
 * alert fires. It is the most dangerous tool here precisely because it is quiet.
 */
export const DESTRUCTIVE_TOOLS: readonly string[] = [
  'delete_domain',
  'delete_mailbox',
  'delete_user',
  'delete_dkim_key',
  'update_dkim_key',
  'delete_queue_items',
] as const;

/**
 * Tools that cannot destroy anything but can be abused to act outwardly in the
 * operator's name.
 *
 * `send_email` is the whole category. A model that has read an injected
 * instruction can be steered into sending mail from a domain the recipient
 * trusts, which is a phishing primitive rather than an outage. It is separated
 * from DESTRUCTIVE because the remedy differs: destruction is about data loss,
 * this is about reputation and abuse.
 */
export const OUTBOUND_TOOLS: readonly string[] = ['send_email'] as const;

export type ToolTier = 'read' | 'write' | 'destructive' | 'outbound';

export interface ToolPolicyOptions {
  /** True when the server is reachable over the network rather than stdio. */
  remote: boolean;
  /** Opt-in for the tools in DESTRUCTIVE_TOOLS. Defaults to false. */
  enableDestructive: boolean;
  /** Opt-in for the tools in OUTBOUND_TOOLS. Defaults to false. */
  enableOutbound: boolean;
}

export interface PolicyDecision {
  allowed: boolean;
  tier: ToolTier;
  /** Populated only when `allowed` is false. Safe to log. */
  reason?: string;
}

/**
 * Classify a tool by name.
 *
 * Classification is by explicit list rather than by matching on `delete_`,
 * because the two tools most worth gating — `update_dkim_key` and `send_email`
 * — would both pass a prefix check.
 */
export function tierOf(toolName: string): ToolTier {
  if (DESTRUCTIVE_TOOLS.includes(toolName)) return 'destructive';
  if (OUTBOUND_TOOLS.includes(toolName)) return 'outbound';
  if (/^(list|get|check|test|health)/.test(toolName)) return 'read';
  return 'write';
}

/**
 * Tool exposure policy.
 *
 * Construct once at startup and consult before every `register()` call.
 */
export class ToolPolicy {
  constructor(private readonly options: ToolPolicyOptions) {}

  /** Whether a tool may be registered in this deployment. */
  evaluate(toolName: string): PolicyDecision {
    const tier = tierOf(toolName);

    if (tier === 'destructive' && !this.options.enableDestructive) {
      return {
        allowed: false,
        tier,
        reason:
          'destructive tools are disabled; set MCP_ENABLE_DESTRUCTIVE_TOOLS=true to enable',
      };
    }

    if (tier === 'outbound' && !this.options.enableOutbound) {
      return {
        allowed: false,
        tier,
        reason:
          'outbound mail tools are disabled; set MCP_ENABLE_OUTBOUND_TOOLS=true to enable',
      };
    }

    return { allowed: true, tier };
  }

  isAllowed(toolName: string): boolean {
    return this.evaluate(toolName).allowed;
  }

  /**
   * Warnings to emit at startup.
   *
   * Returned rather than logged so the caller owns the logger, and so this stays
   * testable without capturing output.
   */
  warnings(): string[] {
    const out: string[] = [];

    if (this.options.enableDestructive && this.options.remote) {
      out.push(
        'DESTRUCTIVE TOOLS ARE ENABLED ON A NETWORK-REACHABLE TRANSPORT. ' +
          `Tools that can permanently destroy mail (${DESTRUCTIVE_TOOLS.join(', ')}) ` +
          'are callable by a model that may have read untrusted content. ' +
          'Confirm the OAuth configuration and the mailcow API key scope before relying on this.',
      );
    }

    if (this.options.enableOutbound && this.options.remote) {
      out.push(
        'OUTBOUND MAIL TOOLS ARE ENABLED ON A NETWORK-REACHABLE TRANSPORT. ' +
          'A model that has read untrusted content can be steered into sending mail ' +
          'from your domains.',
      );
    }

    return out;
  }

  /** Summary for logs and for the `get_config` tool. */
  describe(): Record<string, unknown> {
    return {
      remote: this.options.remote,
      destructiveToolsEnabled: this.options.enableDestructive,
      outboundToolsEnabled: this.options.enableOutbound,
      destructiveTools: DESTRUCTIVE_TOOLS,
      outboundTools: OUTBOUND_TOOLS,
    };
  }
}
