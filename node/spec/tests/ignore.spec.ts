import { beforeEach, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as scanner from '../../lib/scanner';
import { canonicalizePath, ignorePatternToRegExp, isIgnored } from '../../lib/ignore';
import { parseIgnoreFile } from '../../lib/parseIgnoreFile';
import { Finding, Options, Repository } from '../../lib/types';
import { options } from '../options';

const findings: Finding[] = [];
scanner.on('vulnerable-dependency-found', (finding) => findings.push(finding));
beforeEach(() => {
  findings.length = 0;
});

function repoWith(extractors: Repository['sample']['extractors']): Repository {
  return {
    sample: {
      extractors,
      vulnerabilities: [
        {
          below: '2.0.0',
          severity: 'high',
          cwe: ['CWE-79'],
          identifiers: { CVE: ['CVE-2026-1234'] },
          info: ['https://example.com/advisory'],
        },
      ],
    },
  };
}

const jsRepo = repoWith({ filename: ['sample-([0-9.]+)[.]js'] });
const deepRepo = repoWith({
  ast: ['//AssignmentExpression[/:left/:property/:name == "version"]/:right/:value'],
});

function ignoreOptions(dir: string, patterns: string[]): Options {
  const parsed = patterns.map((pattern) => (pattern.startsWith('@') ? pattern.slice(1) : pattern));
  return {
    ...options,
    deep: true,
    ignore: { paths: parsed.map(ignorePatternToRegExp), pathsAsString: parsed },
    path: dir,
  };
}

describe('ignore pattern matching', () => {
  it('matches only complete path segments, including the directory itself and its children', () => {
    const ignore = ignorePatternToRegExp('vendor');
    assert.equal(isIgnored('/proj/vendor', [ignore]), true);
    assert.equal(isIgnored('/proj/vendor/app.js', [ignore]), true);
    assert.equal(isIgnored('/proj/vendor/sub/app.js', [ignore]), true);
  });

  it('does not match sibling prefixes or files containing the segment name', () => {
    const ignore = ignorePatternToRegExp('vendor');
    assert.equal(isIgnored('/proj/vendor-evil/app.js', [ignore]), false);
    assert.equal(isIgnored('/proj/evvendor/app.js', [ignore]), false);
    assert.equal(isIgnored('/proj/src/vendor.js', [ignore]), false);
  });

  it('does not collide with absolute path prefixes', () => {
    const ignore = ignorePatternToRegExp(path.join('/srv', 'proj', 'vendor'));
    assert.equal(isIgnored(path.join('/srv', 'proj', 'vendor', 'app.js'), [ignore]), true);
    assert.equal(isIgnored(path.join('/srv', 'proj', 'vendor-evil', 'app.js'), [ignore]), false);
    assert.equal(isIgnored(path.join('/srv', 'other', 'proj', 'vendor', 'app.js'), [ignore]), false);
  });

  it('keeps glob semantics while enforcing segment boundaries', () => {
    assert.equal(isIgnored('/proj/vendor-evil.js', [ignorePatternToRegExp('vendor-*.js')]), true);
    assert.equal(isIgnored('/proj/vendor-evil/app.js', [ignorePatternToRegExp('vendor-*.js')]), false);
    assert.equal(isIgnored('/proj/libs/a.js', [ignorePatternToRegExp('libs/*.js')]), true);
    assert.equal(isIgnored('/proj/libs/sub/a.js', [ignorePatternToRegExp('libs/*.js')]), false);
    assert.equal(isIgnored('/proj/vendor/a/b.js', [ignorePatternToRegExp('vendor/**')]), true);
  });

  it('ignores trailing slashes and dot segments without weakening boundaries', () => {
    assert.equal(isIgnored('/proj/vendor/app.js', [ignorePatternToRegExp('vendor/')]), true);
    assert.equal(isIgnored('/proj/vendor-evil/app.js', [ignorePatternToRegExp('vendor/')]), false);
    assert.equal(
      isIgnored(path.resolve(path.join('proj', 'vendor', 'x.js')), [ignorePatternToRegExp('./vendor')]),
      true,
    );
    assert.equal(isIgnored('/proj/app.js', [ignorePatternToRegExp('app.js')]), true);
    assert.equal(isIgnored('/proj/xapp.js', [ignorePatternToRegExp('app.js')]), false);
  });

  it('matches relative @-rules regardless of the current working directory', () => {
    const relativeIgnore = ignorePatternToRegExp('vendor/app.js');
    assert.equal(isIgnored(path.join('vendor', 'app.js'), [relativeIgnore]), true);
    assert.equal(isIgnored(path.resolve(path.join('vendor', 'app.js')), [relativeIgnore]), true);
    assert.equal(isIgnored(path.join('vendor-evil', 'app.js'), [relativeIgnore]), false);
  });

  it('canonicalizes Windows-style separators', () => {
    assert.equal(canonicalizePath(path.join('proj', 'vendor', 'app.js')).includes('\\'), false);
    assert.equal(isIgnored('proj\\vendor\\app.js', [ignorePatternToRegExp(path.join('proj', 'vendor'))]), true);
  });
});

describe('scanner ignores', () => {
  it('parses @ relative rules, plain paths and JSON path descriptors into boundary patterns', (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-ignore-file-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const plain = path.join(dir, '.retireignore');
    fs.writeFileSync(plain, '@vendor\nlibs/a-*.js\n');
    const config: Options = {
      ...options,
      ignore: { paths: [], pathsAsString: [], descriptors: [] },
    };
    const patterns = parseIgnoreFile(plain, config);
    assert.deepEqual(patterns, ['vendor', path.resolve('libs/a-*.js')]);
    assert.equal(isIgnored(path.join(dir, 'vendor', 'app.js'), patterns), true);
    assert.equal(isIgnored(path.join(dir, 'vendor-evil', 'app.js'), patterns), false);

    const json = path.join(dir, '.retireignore.json');
    fs.writeFileSync(json, JSON.stringify([{ path: 'bower_components', justification: 'vendored' }]));
    const jsonConfig: Options = {
      ...options,
      ignore: { paths: [], pathsAsString: [], descriptors: [] },
    };
    const jsonPatterns = parseIgnoreFile(json, jsonConfig);
    assert.deepEqual(jsonPatterns, ['bower_components']);
    assert.equal(isIgnored(path.join(dir, 'bower_components', 'x.js'), jsonPatterns), true);
    assert.equal(isIgnored(path.join(dir, 'bower_components-evil', 'x.js'), jsonPatterns), false);
  });

  it('skips ignored JavaScript files but still scans sibling prefixes', async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-ignore-js-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const ignored = path.join(dir, 'vendor', 'sample-1.0.js');
    const evil = path.join(dir, 'vendor-evil', 'sample-1.0.js');
    fs.mkdirSync(path.dirname(ignored), { recursive: true });
    fs.mkdirSync(path.dirname(evil), { recursive: true });
    fs.writeFileSync(ignored, '');
    fs.writeFileSync(evil, '');

    const config = ignoreOptions(dir, ['@vendor']);
    await scanner.scanJsFile(ignored, jsRepo, config);
    await scanner.scanJsFile(evil, jsRepo, config);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, evil);
  });

  it('skips ignored Bower files but still scans sibling prefixes', async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-ignore-bower-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const ignored = path.join(dir, 'vendor', 'bower.json');
    const evil = path.join(dir, 'vendor-evil', 'bower.json');
    fs.mkdirSync(path.dirname(ignored), { recursive: true });
    fs.mkdirSync(path.dirname(evil), { recursive: true });
    for (const file of [ignored, evil]) {
      fs.writeFileSync(file, JSON.stringify({ name: 'sample', version: '1.0' }));
    }

    const config = ignoreOptions(dir, ['vendor']);
    await scanner.scanBowerFile(ignored, jsRepo, config);
    await scanner.scanBowerFile(evil, jsRepo, config);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, evil);
  });

  it('applies segment-boundary ignores to deep scan results', async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-ignore-deep-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const ignored = path.join(dir, 'vendor', 'bundle.js');
    const evil = path.join(dir, 'vendor-evil', 'bundle.js');
    fs.mkdirSync(path.dirname(ignored), { recursive: true });
    fs.mkdirSync(path.dirname(evil), { recursive: true });
    for (const file of [ignored, evil]) {
      fs.writeFileSync(file, 'var component = {}; component.version = "1.0.0";');
    }

    const config = ignoreOptions(dir, ['vendor']);
    await scanner.scanJsFile(ignored, deepRepo, config);
    await scanner.scanJsFile(evil, deepRepo, config);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, evil);
    assert.equal(findings[0].results[0].component, 'sample');
    assert.equal(findings[0].results[0].version, '1.0.0');
  });
});
