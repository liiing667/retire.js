import path from 'path';

/**
 * Normalizes a path so patterns and scanned files can be compared regardless of
 * platform: backslashes become forward slashes and relative `./` segments are
 * resolved without turning relative patterns into absolute paths.
 */
export function canonicalizePath(file: string): string {
  return path.normalize(file).replace(/\\/g, '/');
}

function globToRegExpSource(pattern: string): string {
  const canonical = canonicalizePath(pattern).replace(/\/+$/, '');
  const escaped = canonical.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  return escaped.replace(/[*]{1,2}/g, (stars) => (stars.length === 2 ? '.*' : '[^/]*'));
}

/**
 * Converts an ignore pattern (a resolved absolute path, a relative `@`-rule
 * pattern, or a glob) into a regular expression that only matches complete
 * path segments of a canonical path. A directory pattern matches the directory
 * itself and everything below it, while a file pattern matches only that file.
 */
export function ignorePatternToRegExp(pattern: string): RegExp {
  return new RegExp(`(?:^|/)${globToRegExpSource(pattern)}(?:/|$)`);
}

/**
 * Returns true when the given file is matched by any of the ignore patterns.
 * Both the file as reported by the walker and its resolved absolute path are
 * checked so relative `@`-rules and absolute ignore entries stay compatible.
 */
export function isIgnored(file: string, ignorePaths: Array<string | RegExp>): boolean {
  const canonicalFile = canonicalizePath(file);
  const absoluteFile = canonicalizePath(path.resolve(file));
  return ignorePaths.some((entry) => {
    const ignore = entry instanceof RegExp ? entry : ignorePatternToRegExp(entry);
    if (ignore.test(canonicalFile) || ignore.test(absoluteFile)) return true;
    if (entry instanceof RegExp || path.isAbsolute(entry)) return false;
    return new RegExp(`^${globToRegExpSource(entry)}(?:/|$)`).test(absoluteFile);
  });
}
