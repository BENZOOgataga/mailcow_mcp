/**
 * Tool exposure policy.
 *
 * The last test in this file is the important one, and it exists because of a
 * specific mistake: the destructive list was originally built by thinking
 * about which tools *delete* things. `update_mailbox` and `update_user` accept
 * a `password` field, delete nothing, and were therefore registered in the
 * default remote configuration — where a model could reset `postmaster@`'s
 * password and hand whoever read it full control of the domain over IMAP.
 *
 * Enumerating a deny-list by hand is how that happened, so the fix is not to
 * add two names. It is a test that derives the requirement from the source: a
 * tool whose input schema accepts a credential must be gated, and a new tool
 * that accepts one fails this test on the day it is written.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  ToolPolicy,
  DESTRUCTIVE_TOOLS,
  CREDENTIAL_TOOLS,
  OUTBOUND_TOOLS,
  tierOf,
} from '../../../src/tools/policy';

describe('ToolPolicy', () => {
  const safeRemote = new ToolPolicy({
    remote: true,
    enableDestructive: false,
    enableCredential: false,
    enableOutbound: false,
  });
  const openRemote = new ToolPolicy({
    remote: true,
    enableDestructive: true,
    enableCredential: true,
    enableOutbound: true,
  });

  it('withholds every destructive tool by default', () => {
    for (const tool of DESTRUCTIVE_TOOLS) {
      expect(safeRemote.isAllowed(tool)).toBe(false);
    }
  });

  it('withholds every credential-setting tool by default', () => {
    for (const tool of CREDENTIAL_TOOLS) {
      expect(safeRemote.isAllowed(tool)).toBe(false);
    }
  });

  it('withholds every outbound tool by default', () => {
    for (const tool of OUTBOUND_TOOLS) {
      expect(safeRemote.isAllowed(tool)).toBe(false);
    }
  });

  it('allows them once explicitly enabled', () => {
    for (const tool of [...DESTRUCTIVE_TOOLS, ...CREDENTIAL_TOOLS, ...OUTBOUND_TOOLS]) {
      expect(openRemote.isAllowed(tool)).toBe(true);
    }
  });

  it('allows ordinary read and write tools', () => {
    for (const tool of ['list_domains', 'get_mailbox', 'create_domain', 'flush_queue']) {
      expect(safeRemote.isAllowed(tool)).toBe(true);
    }
  });

  it('classifies by explicit list, not by name prefix', () => {
    // Both would pass a naive /^delete_/ check, and both are the reason that
    // check is not what the policy uses.
    expect(tierOf('update_dkim_key')).toBe('destructive');
    expect(tierOf('send_email')).toBe('outbound');
  });

  it('warns when destructive tools are enabled on a network transport', () => {
    expect(openRemote.warnings().length).toBeGreaterThan(0);
    expect(
      new ToolPolicy({
        remote: false,
        enableDestructive: true,
        enableCredential: true,
        enableOutbound: true,
      }).warnings(),
    ).toHaveLength(0);
  });

  /**
   * Derive the requirement from the source rather than from memory.
   *
   * Walks every tool module, pairs each `readonly name = '...'` with the class
   * body that follows it, and asserts that any tool whose input schema accepts
   * a credential field is gated. Adding a tool that takes a password without
   * gating it fails here.
   */
  it('gates every tool whose input schema accepts a credential', () => {
    const toolsDir = join(__dirname, '..', '..', '..', 'src', 'tools');

    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full);
        else if (entry.endsWith('.ts')) files.push(full);
      }
    };
    walk(toolsDir);

    const CREDENTIAL_FIELDS = /\b(password|secret|token|api_key|private_key)\s*:/;
    const ungated: string[] = [];

    for (const file of files) {
      const source = readFileSync(file, 'utf8');

      // Split on tool-class name declarations; each chunk is one tool's body.
      const chunks = source.split(/readonly name = '/).slice(1);
      for (const chunk of chunks) {
        const name = chunk.slice(0, chunk.indexOf("'"));
        if (!name) continue;

        // Only look at the input schema, not the execute() body — a handler
        // legitimately reads input.password for a tool that is meant to take one.
        const schemaStart = chunk.indexOf('inputSchema');
        if (schemaStart === -1) continue;
        const schema = chunk.slice(schemaStart, schemaStart + 4000);

        const tier = tierOf(name);
        if (CREDENTIAL_FIELDS.test(schema) && tier !== 'credential' && tier !== 'destructive') {
          ungated.push(name);
        }
      }
    }

    expect(ungated).toEqual([]);
  });
});
