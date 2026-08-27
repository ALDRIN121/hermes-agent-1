import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'vitest'

import { findPackedPayload, relativizePayloadLinks, stripFetchCache } from './materialize-payload-links.mjs'

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-relativize-'))
}

test('findPackedPayload locates the mac nested payload', () => {
  const root = tempRoot()
  try {
    const app = path.join(root, 'Hermes.app')
    const payload = path.join(app, 'Contents', 'Resources', 'agent-payload')
    fs.mkdirSync(payload, { recursive: true })
    assert.equal(findPackedPayload(app, 'darwin'), payload)
    assert.equal(findPackedPayload(root, 'darwin'), payload)
    assert.equal(findPackedPayload(root, 'linux'), null)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('relativizePayloadLinks rewrites an absolute in-payload symlink to relative', () => {
  if (process.platform === 'win32') return
  const root = tempRoot()
  try {
    const store = path.join(root, 'tools', 'python', 'bin')
    const venv = path.join(root, 'venv', 'bin')
    fs.mkdirSync(store, { recursive: true })
    fs.mkdirSync(venv, { recursive: true })
    const real = path.join(store, 'python3.11')
    fs.writeFileSync(real, 'interpreter-bytes')
    const link = path.join(venv, 'python3')
    // The absolute form uv --relocatable writes on POSIX.
    fs.symlinkSync(real, link)
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true)

    const n = relativizePayloadLinks(root)
    assert.equal(n, 1)
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true)
    const target = fs.readlinkSync(link)
    assert.equal(target.startsWith(path.sep), false) // now relative
    assert.equal(path.resolve(venv, target), real)
    assert.equal(fs.readFileSync(link, 'utf8'), 'interpreter-bytes') // resolves
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('relativizePayloadLinks throws when a symlink escapes the payload', () => {
  if (process.platform === 'win32') return
  const root = tempRoot()
  try {
    const outside = path.join(os.tmpdir(), `hermes-outside-${Date.now()}`)
    fs.mkdirSync(outside, { recursive: true })
    fs.writeFileSync(path.join(outside, 'python3.11'), 'x')
    const venv = path.join(root, 'venv', 'bin')
    fs.mkdirSync(venv, { recursive: true })
    fs.symlinkSync(path.join(outside, 'python3.11'), path.join(venv, 'python3'))
    assert.throws(() => relativizePayloadLinks(root), /outside the payload/)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('relativizePayloadLinks leaves already-relative links alone', () => {
  if (process.platform === 'win32') return
  const root = tempRoot()
  try {
    const store = path.join(root, 'tools', 'python', 'bin')
    const venv = path.join(root, 'venv', 'bin')
    fs.mkdirSync(store, { recursive: true })
    fs.mkdirSync(venv, { recursive: true })
    const real = path.join(store, 'python3.11')
    fs.writeFileSync(real, 'interpreter-bytes')
    const link = path.join(venv, 'python3')
    fs.symlinkSync(path.relative(venv, real), link)

    assert.equal(relativizePayloadLinks(root), 0)
    assert.equal(fs.readlinkSync(link), path.relative(venv, real))
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('stripFetchCache removes only fetch- dirs under tools/', () => {
  const root = tempRoot()
  try {
    const tools = path.join(root, 'tools')
    fs.mkdirSync(path.join(tools, 'fetch-546f7f8a6c70ff13'), { recursive: true })
    fs.writeFileSync(path.join(tools, 'fetch-546f7f8a6c70ff13', 'uv.tar.gz'), 'x')
    fs.mkdirSync(path.join(tools, 'uv-0.12.3-darwin-arm64'), { recursive: true })
    fs.writeFileSync(path.join(tools, 'uv-0.12.3-darwin-arm64', 'uv'), 'bin')
    assert.equal(stripFetchCache(root), 1)
    assert.equal(fs.existsSync(path.join(tools, 'fetch-546f7f8a6c70ff13')), false)
    assert.equal(fs.existsSync(path.join(tools, 'uv-0.12.3-darwin-arm64', 'uv')), true)
    assert.equal(stripFetchCache(root), 0)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('stripFetchCache also drops leftover chromium store entries', () => {
  const root = tempRoot()
  try {
    const tools = path.join(root, 'tools')
    fs.mkdirSync(path.join(tools, 'chromium-1208'), { recursive: true })
    fs.writeFileSync(path.join(tools, 'chromium-1208', 'INSTALLATION_COMPLETE'), '')
    fs.mkdirSync(path.join(tools, 'chromium_headless_shell-1208'), { recursive: true })
    fs.mkdirSync(path.join(tools, 'uv-0.12.3-darwin-arm64'), { recursive: true })
    fs.writeFileSync(path.join(tools, 'uv-0.12.3-darwin-arm64', 'uv'), 'bin')
    assert.equal(stripFetchCache(root), 2)
    assert.equal(fs.existsSync(path.join(tools, 'chromium-1208')), false)
    assert.equal(fs.existsSync(path.join(tools, 'chromium_headless_shell-1208')), false)
    assert.equal(fs.existsSync(path.join(tools, 'uv-0.12.3-darwin-arm64', 'uv')), true)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('relativizePayloadLinks does not touch a framework file-symlink (not under venv/bin)', () => {
  if (process.platform === 'win32') return
  const root = tempRoot()
  try {
    const versioned = path.join(root, 'tools', 'chromium-1208', 'F.framework', 'Versions', 'A')
    fs.mkdirSync(versioned, { recursive: true })
    const real = path.join(versioned, 'F')
    fs.writeFileSync(real, 'machO')
    const link = path.join(root, 'tools', 'chromium-1208', 'F.framework', 'F')
    fs.symlinkSync(path.join('Versions', 'A', 'F'), link)
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true)

    assert.equal(relativizePayloadLinks(root), 0)
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
