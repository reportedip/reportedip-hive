<?php
/**
 * Translation I/O helper for the German PO file.
 *
 * Two modes power a repeatable translation pipeline:
 *
 *   export <po> <outdir> [chunkSize]   Write untranslated entries as JSON chunks
 *                                      (chunk-NN.json), with unescaped source text
 *                                      and source references for context.
 *   import <po> <outdir>               Read chunk-NN.out.json files and fill the
 *                                      matching msgstr values back into the PO,
 *                                      escaping correctly. Only fills entries that
 *                                      are still untranslated (empty msgstr).
 *
 * Entries are matched on the (context, msgid) pair, so the same string under
 * different gettext contexts stays distinct.
 *
 * @package ReportedIP_Hive
 * @author  Patrick Schlesinger <ps@cms-admins.de>
 * @license GPL-2.0-or-later
 * @since   2.0.18
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Bin;

/**
 * Reads a JSON file tolerantly, escaping raw control characters that some
 * generators emit unescaped (notably U+0004 inside key strings), which would
 * otherwise make the JSON invalid.
 *
 * @param string $file File path.
 * @return mixed Decoded value, or null on unrecoverable error.
 */
function read_json_tolerant(string $file)
{
    $raw = (string) file_get_contents($file);
    $decoded = json_decode($raw, true);
    if (null !== $decoded) {
        return $decoded;
    }
    $escaped = preg_replace_callback(
        '/[\x00-\x08\x0B\x0C\x0E-\x1F]/',
        static function (array $m): string {
            return sprintf('\\u%04x', ord($m[0]));
        },
        $raw
    );
    return json_decode((string) $escaped, true);
}

/**
 * Decodes a PO-escaped string into its literal value.
 *
 * @param string $value Escaped PO string content (without surrounding quotes).
 * @return string
 */
function po_unescape(string $value): string
{
    return strtr(
        $value,
        array(
            '\\n'  => "\n",
            '\\t'  => "\t",
            '\\r'  => "\r",
            '\\"'  => '"',
            '\\\\' => '\\',
        )
    );
}

/**
 * Encodes a literal string into a single-line PO-escaped string.
 *
 * @param string $value Literal string.
 * @return string
 */
function po_escape(string $value): string
{
    return strtr(
        $value,
        array(
            '\\' => '\\\\',
            '"'  => '\\"',
            "\n" => '\\n',
            "\t" => '\\t',
            "\r" => '\\r',
        )
    );
}

/**
 * Splits raw PO content into entry blocks (separated by blank lines).
 *
 * @param string $content PO file content (LF line endings).
 * @return string[]
 */
function po_blocks(string $content): array
{
    return preg_split("/\n\n+/", trim($content)) ?: array();
}

/**
 * Concatenates the quoted-string payload following a keyword line, including
 * continuation lines, and returns the unescaped literal.
 *
 * @param string[] $lines     Block lines.
 * @param int      $start     Index of the keyword line.
 * @param string   $remainder Inline payload on the keyword line (already matched).
 * @return string
 */
function collect_string(array $lines, int $start, string $remainder): string
{
    $raw   = $remainder;
    $total = count($lines);
    for ($i = $start + 1; $i < $total; $i++) {
        if (preg_match('/^"(.*)"$/s', $lines[$i], $m)) {
            $raw .= $m[1];
            continue;
        }
        break;
    }
    return po_unescape($raw);
}

/**
 * Parses one block into a structured entry, or null for the header / comments-only.
 *
 * @param string $block Entry block.
 * @return array{context:?string,singular:string,plural:?string,refs:string[],untranslated:bool}|null
 */
function parse_entry(string $block): ?array
{
    $lines    = explode("\n", $block);
    $context  = null;
    $singular = null;
    $plural   = null;
    $refs     = array();
    $msgstrs  = array();
    $total    = count($lines);

    for ($i = 0; $i < $total; $i++) {
        $line = $lines[$i];
        if ('' === $line) {
            continue;
        }
        if ('#' === $line[0]) {
            if (preg_match('/^#:\s*(.+)$/', $line, $m)) {
                $refs[] = trim($m[1]);
            }
            continue;
        }
        if (preg_match('/^msgctxt\s+"(.*)"$/s', $line, $m)) {
            $context = collect_string($lines, $i, $m[1]);
            continue;
        }
        if (preg_match('/^msgid_plural\s+"(.*)"$/s', $line, $m)) {
            $plural = collect_string($lines, $i, $m[1]);
            continue;
        }
        if (preg_match('/^msgid\s+"(.*)"$/s', $line, $m)) {
            $singular = collect_string($lines, $i, $m[1]);
            continue;
        }
        if (preg_match('/^msgstr(?:\[\d+\])?\s+"(.*)"$/s', $line, $m)) {
            $msgstrs[] = collect_string($lines, $i, $m[1]);
            continue;
        }
    }

    if (null === $singular || '' === $singular) {
        return null;
    }

    $untranslated = true;
    foreach ($msgstrs as $value) {
        if ('' !== $value) {
            $untranslated = false;
            break;
        }
    }

    return array(
        'context'      => $context,
        'singular'     => $singular,
        'plural'       => $plural,
        'refs'         => $refs,
        'untranslated' => $untranslated,
    );
}

/**
 * Builds the stable match key for an entry.
 *
 * @param ?string $context Gettext context.
 * @param string  $msgid   Singular msgid (literal).
 * @return string
 */
function entry_key(?string $context, string $msgid): string
{
    return ($context ?? '') . "\x04" . $msgid;
}

/**
 * Normalises a match key so that no-context entries compare equal whether or
 * not the producing agent kept the leading U+0004 context separator.
 *
 * @param string $key Raw key.
 * @return string
 */
function normalize_key(string $key): string
{
    return ("\x04" === substr($key, 0, 1)) ? substr($key, 1) : $key;
}

/**
 * Runs export mode.
 *
 * @param string $po        PO path.
 * @param string $outdir    Output directory for chunk files.
 * @param int    $chunkSize Entries per chunk.
 * @return int
 */
function run_export(string $po, string $outdir, int $chunkSize): int
{
    $content = str_replace("\r\n", "\n", (string) file_get_contents($po));
    $items   = array();

    foreach (po_blocks($content) as $block) {
        $entry = parse_entry($block);
        if (null === $entry || !$entry['untranslated']) {
            continue;
        }
        $items[] = array(
            'key'       => entry_key($entry['context'], $entry['singular']),
            'context'   => $entry['context'],
            'singular'  => $entry['singular'],
            'plural'    => $entry['plural'],
            'reference' => $entry['refs'][0] ?? '',
        );
    }

    return write_chunks($items, $outdir, $chunkSize, 'untranslated entries');
}

/**
 * Writes a list of entries to chunk-NN.json files, clearing stale chunks first.
 *
 * @param array<int, array<string, mixed>> $items     Entries to chunk.
 * @param string                           $outdir    Output directory.
 * @param int                              $chunkSize Entries per chunk.
 * @param string                           $label     Noun used in the summary line.
 * @return int
 */
function write_chunks(array $items, string $outdir, int $chunkSize, string $label): int
{
    if (!is_dir($outdir)) {
        mkdir($outdir, 0777, true);
    }
    array_map('unlink', glob($outdir . '/chunk-*.json') ?: array());

    $chunks = array_chunk($items, max(1, $chunkSize));
    foreach ($chunks as $i => $chunk) {
        file_put_contents(
            sprintf('%s/chunk-%02d.json', $outdir, $i),
            json_encode($chunk, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        );
    }

    fwrite(STDOUT, sprintf("Exported %d %s into %d chunks.\n", count($items), $label, count($chunks)));
    return 0;
}

/**
 * Runs export-review mode: dumps EVERY entry (translated or not) with its
 * current German translation so a reviewer can critique and improve it in
 * context, rather than translating from scratch.
 *
 * @param string $po        PO path.
 * @param string $outdir    Output directory for chunk files.
 * @param int    $chunkSize Entries per chunk.
 * @return int
 */
function run_export_review(string $po, string $outdir, int $chunkSize): int
{
    $content = str_replace("\r\n", "\n", (string) file_get_contents($po));
    $items   = array();

    foreach (po_blocks($content) as $block) {
        $entry = parse_entry($block);
        if (null === $entry) {
            continue;
        }
        $msgstrs = parse_msgstrs($block);
        $items[] = array(
            'key'         => entry_key($entry['context'], $entry['singular']),
            'context'     => $entry['context'],
            'en_singular' => $entry['singular'],
            'en_plural'   => $entry['plural'],
            'de_singular' => $msgstrs[0] ?? '',
            'de_plural'   => null !== $entry['plural'] ? ($msgstrs[1] ?? '') : null,
            'reference'   => $entry['refs'][0] ?? '',
        );
    }

    return write_chunks($items, $outdir, $chunkSize, 'entries for review');
}

/**
 * Extracts the unescaped msgstr / msgstr[n] values from a block, in order.
 *
 * @param string $block Entry block.
 * @return array<int, string>
 */
function parse_msgstrs(string $block): array
{
    $lines = explode("\n", $block);
    $out   = array();
    for ($i = 0; $i < count($lines); $i++) {
        if (preg_match('/^msgstr(?:\[\d+\])?\s+"(.*)"$/s', $lines[$i], $m)) {
            $out[] = collect_string($lines, $i, $m[1]);
        }
    }
    return $out;
}

/**
 * Runs import mode: fills translations from chunk-NN.out.json back into the PO.
 *
 * @param string $po     PO path.
 * @param string $outdir Directory holding chunk-NN.out.json files.
 * @return int
 */
function run_import(string $po, string $outdir, bool $overwrite = false): int
{
    $map = array();
    foreach (glob($outdir . '/chunk-*.out.json') ?: array() as $file) {
        $rows = read_json_tolerant($file);
        if (!is_array($rows)) {
            fwrite(STDERR, "Malformed output file: $file\n");
            return 1;
        }
        foreach ($rows as $row) {
            if (!isset($row['key'])) {
                continue;
            }
            $map[normalize_key((string) $row['key'])] = $row;
        }
    }

    if (empty($map)) {
        fwrite(STDERR, "No translations found in $outdir (expected chunk-*.out.json).\n");
        return 1;
    }

    $content = str_replace("\r\n", "\n", (string) file_get_contents($po));
    $blocks  = po_blocks($content);
    $filled  = 0;

    foreach ($blocks as $idx => $block) {
        $entry = parse_entry($block);
        if (null === $entry || ('' === $entry['singular'])) {
            continue;
        }
        if (!$overwrite && !$entry['untranslated']) {
            continue;
        }
        $key = normalize_key(entry_key($entry['context'], $entry['singular']));
        if (!isset($map[$key])) {
            continue;
        }
        $row     = $map[$key];
        $pattern = $overwrite ? '"[^"]*(?:\\\\"[^"]*)*"' : '""';

        if (null !== $entry['plural']) {
            $singular = po_escape((string) ($row['singular'] ?? ''));
            $plural   = po_escape((string) ($row['plural'] ?? ''));
            if ('' === $singular || '' === $plural) {
                continue;
            }
            $block = preg_replace('/^msgstr\[0\] ' . $pattern . '$/m', 'msgstr[0] "' . $singular . '"', $block, 1);
            $block = preg_replace('/^msgstr\[1\] ' . $pattern . '$/m', 'msgstr[1] "' . $plural . '"', $block, 1);
        } else {
            $translation = po_escape((string) ($row['singular'] ?? ''));
            if ('' === $translation) {
                continue;
            }
            $block = preg_replace('/^msgstr ' . $pattern . '$/m', 'msgstr "' . $translation . '"', $block, 1);
        }

        $blocks[$idx] = $block;
        ++$filled;
    }

    file_put_contents($po, implode("\n\n", $blocks) . "\n");
    fwrite(STDOUT, sprintf("%s %d translations in %s.\n", $overwrite ? 'Applied' : 'Filled', $filled, $po));
    return 0;
}

/**
 * Extracts placeholder/markup tokens from a string as a sorted multiset.
 *
 * Covers printf placeholders (%s, %d, %1$s, %%), HTML tags, gettext shortcodes
 * and HTML entities — everything that must survive translation unchanged.
 *
 * @param string $value String to scan.
 * @return string[] Sorted token list.
 */
function tokens(string $value): array
{
    static $patterns = array(
        '/%(?:\d+\$)?[-+0]?\d*(?:\.\d+)?[bcdeEfFgGosuxX%]/',
        '/<\/?[a-zA-Z][^>]*>/',
        '/\[[a-zA-Z_][^\]]*\]/',
        '/&[a-zA-Z]+;|&#\d+;/',
    );
    $tokens = array();
    foreach ($patterns as $pattern) {
        if (preg_match_all($pattern, $value, $m)) {
            foreach ($m[0] as $tok) {
                $tokens[] = $tok;
            }
        }
    }
    sort($tokens);
    return $tokens;
}

/**
 * Validates token integrity of every translation against its source.
 *
 * @param string $workdir Directory with chunk-NN.json and chunk-NN.out.json.
 * @return int 0 if all consistent, 1 otherwise.
 */
function run_validate(string $workdir): int
{
    $source = array();
    foreach (glob($workdir . '/chunk-*.json') ?: array() as $file) {
        if (false !== strpos($file, '.out.json')) {
            continue;
        }
        $rows = read_json_tolerant($file);
        foreach ((array) $rows as $row) {
            if (!isset($row['key'])) {
                continue;
            }
            $source[normalize_key($row['key'])] = array(
                'singular' => $row['singular'] ?? $row['en_singular'] ?? '',
                'plural'   => $row['plural'] ?? $row['en_plural'] ?? null,
            );
        }
    }

    $problems = 0;
    $checked  = 0;
    foreach (glob($workdir . '/chunk-*.out.json') ?: array() as $file) {
        $rows = read_json_tolerant($file);
        if (!is_array($rows)) {
            fwrite(STDERR, 'INVALID JSON: ' . basename($file) . "\n");
            ++$problems;
            continue;
        }
        foreach ($rows as $row) {
            $key = isset($row['key']) ? normalize_key((string) $row['key']) : null;
            if (null === $key || !isset($source[$key])) {
                fwrite(STDERR, 'UNKNOWN KEY in ' . basename($file) . ': ' . json_encode($row['key'] ?? null) . "\n");
                ++$problems;
                continue;
            }
            ++$checked;
            $src = $source[$key];

            if ('' === trim((string) ($row['singular'] ?? ''))) {
                fwrite(STDERR, 'EMPTY translation: ' . substr((string) $src['singular'], 0, 60) . "\n");
                ++$problems;
                continue;
            }
            if (tokens((string) $src['singular']) !== tokens((string) ($row['singular'] ?? ''))) {
                fwrite(STDERR, 'TOKEN MISMATCH (singular): "' . substr((string) $src['singular'], 0, 70) . "\"\n");
                ++$problems;
            }
            if (null !== ($src['plural'] ?? null)) {
                if (tokens((string) $src['plural']) !== tokens((string) ($row['plural'] ?? ''))) {
                    fwrite(STDERR, 'TOKEN MISMATCH (plural): "' . substr((string) $src['plural'], 0, 70) . "\"\n");
                    ++$problems;
                }
            }
        }
    }

    fwrite(STDOUT, sprintf("Validated %d translations; %d problem(s).\n", $checked, $problems));
    return $problems > 0 ? 1 : 0;
}

$mode = $argv[1] ?? '';
if ('export' === $mode && isset($argv[2], $argv[3])) {
    exit(run_export($argv[2], $argv[3], (int) ($argv[4] ?? 65)));
}
if ('export-review' === $mode && isset($argv[2], $argv[3])) {
    exit(run_export_review($argv[2], $argv[3], (int) ($argv[4] ?? 65)));
}
if ('import' === $mode && isset($argv[2], $argv[3])) {
    exit(run_import($argv[2], $argv[3], false));
}
if ('apply' === $mode && isset($argv[2], $argv[3])) {
    exit(run_import($argv[2], $argv[3], true));
}
if ('validate' === $mode && isset($argv[2])) {
    exit(run_validate($argv[2]));
}

fwrite(STDERR, "Usage:\n  po-translate-io.php export <po> <outdir> [chunkSize]\n  po-translate-io.php export-review <po> <outdir> [chunkSize]\n  po-translate-io.php import <po> <outdir>\n  po-translate-io.php apply <po> <outdir>\n  po-translate-io.php validate <outdir>\n");
exit(2);
