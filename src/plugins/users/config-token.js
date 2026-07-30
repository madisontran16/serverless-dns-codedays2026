/*
 * Copyright (c) 2024 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * config-token.js — helpers for blocklist independence.
 *
 * Thin wrapper around the existing blockstamp primitives so that callers
 * don't need to import from multiple modules to build or consume a
 * blocklist token.  The wire format is intentionally identical to the
 * rest of the codebase (rdns-util.js / @serverless-dns/trie/stamp) so
 * existing DoH / DoT clients continue to work without modification.
 */

import { tagsToFlags } from "@serverless-dns/trie/stamp.js";
import * as util from "../../commons/util.js";
import * as rdnsutil from "../rdns-util.js";

/**
 * Encode a list of blocklist tag names into a blockstamp string.
 *
 * @param {string[]} tags  - blocklist tag names (e.g. ["MTF", "KBI"])
 * @param {string}   [flagVersion="1"]
 * @returns {string} blockstamp  (e.g. "1:YAYBACABEDAgAA==")
 */
export function encode(tags, flagVersion = "1") {
  if (util.emptyArray(tags)) return "";
  const uint = tagsToFlags(tags);
  if (util.emptyArray(uint)) return "";
  return rdnsutil.getB64Flag(uint, flagVersion);
}

/**
 * Decode a blockstamp into its constituent parts.
 * Returns the same shape as rdnsutil.unstamp() so callers can use either.
 *
 * @param {string} blockstamp
 * @returns {import("../plugin-response.js").BlockstampInfo}
 */
export function decode(blockstamp) {
  return rdnsutil.unstamp(blockstamp);
}

/**
 * Build ready-to-use DNS setup URLs for a self-hosted deployment.
 *
 * @param {string} baseUrl    - deployment origin, e.g. "https://dns.example.com"
 * @param {string} blockstamp - encoded blocklist stamp (from encode())
 * @returns {{ doh: string, dot: string, configure: string }}
 */
export function setupUrls(baseUrl, blockstamp) {
  // strip trailing slash for consistent URL construction
  const base = (baseUrl || "").replace(/\/+$/, "");

  // DoH: https://dns.example.com/<stamp>/dns-query
  const doh = util.emptyString(blockstamp)
    ? base + "/dns-query"
    : base + "/" + blockstamp + "/dns-query";

  // DoT hostname embeds the b32-encoded stamp as a subdomain label.
  // We expose the raw DoT URL template here; the stamp itself must be
  // b32-encoded by the client for DoT — here we just point at the base host.
  const dot = util.emptyString(blockstamp)
    ? base
    : base + "  (DoT stamp: " + blockstamp + ")";

  // configure page on the user's own domain
  const configure = util.emptyString(blockstamp)
    ? base + "/configure"
    : base + "/configure#" + blockstamp;

  return { doh, dot, configure };
}
