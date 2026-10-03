"""Execute the browser export adapter without a browser or network."""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("node") is None, reason="optional Node.js runtime unavailable")
def test_exports_authenticate_in_headers_not_urls():
    script = r'''
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync("web/app.js", "utf8");
const fn = source.slice(source.indexOf("function updateExportLinks("), source.indexOf("function renderIdentityCandidates("));
const links = Object.fromEntries(["html", "json", "csv", "stix"].map(f => ["export-" + f, {}]));
const panel = {style: {}};
const calls = [];
let downloads = 0;
const scope = {
  document: {getElementById: id => id === "export-panel" ? panel : links[id],
             createElement: () => ({click: () => downloads++})},
  localStorage: {getItem: () => "test-export-credential"},
  fetch: async (url, opts) => { calls.push({url, opts}); return {ok: true, blob: async () => ({})}; },
  URL: {createObjectURL: () => "blob:local-test", revokeObjectURL: () => {}},
  setTimeout: fn => fn(), window: {alert: msg => {throw new Error(msg);}},
};
vm.runInNewContext(fn, scope);
scope.updateExportLinks({username: "alice", scan_id: 7});
(async () => {
  for (const link of Object.values(links)) {
    assert.ok(!link.href.includes("token="));
    await link.onclick({preventDefault: () => {}});
  }
  assert.equal(downloads, 4);
  assert.equal(calls.length, 4);
  for (const call of calls) {
    assert.equal(call.opts.headers.Authorization, "Bearer test-export-credential");
    assert.ok(!call.url.includes("test-export-credential"));
  }
})().catch(err => {console.error(err); process.exitCode = 1;});
'''
    subprocess.run(
        [shutil.which("node"), "-e", script],
        cwd=Path(__file__).resolve().parents[1], check=True, timeout=10,
        capture_output=True, text=True,
    )
