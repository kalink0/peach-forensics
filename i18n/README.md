# Translating Peach

Peach's interface text lives in one plain-text file per language:

```
i18n/en/peach.ftl   English — the reference, maintained with the code
i18n/de/peach.ftl   German
i18n/<code>/peach.ftl   any other language
```

Translating means editing one of these files. You don't need Rust or a
build setup: open a pull request, and CI checks your file and reports the
result on the PR.

## The file format

The files use [Fluent](https://projectfluent.org/fluent/guide/). Each line
is one message: an id on the left, the text on the right.

```
settings-title = Settings
common-cancel = Cancel
```

Translate only the text **right** of the `=`. Never change the id on the
left: Peach looks messages up by id.

Lines starting with `#` are comments. In the English file they say where a
text appears and what to keep as-is. Comments in your file are optional.

### Placeholders

Text in `{ $name }` is filled in by Peach, for example a number or a path:

```
settings-load-threads-on-this-machine = ({ $count } on this machine)
```

Keep every placeholder, spelled exactly as in English. You can move it to
wherever your language's word order needs it:

```
settings-load-threads-on-this-machine = ({ $count } auf diesem Rechner)
```

### Plural forms

When a sentence depends on a number, Fluent can choose between forms:

```
records-skipped = { $count ->
    [one] One record skipped
   *[other] { $count } records skipped
}
```

The variant names (`one`, `other`, and for some languages `few`, `many`)
follow the [Unicode plural rules](https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html)
for your language. The variant marked `*` is the default and is required.
Use as many or as few variants as your language needs.

### Long text

A message can continue on the next lines if they're indented:

```
settings-memory-limit-help =
    RAM the timeline database may use. Beyond it, data
    spills to a temp folder next to the session file.
```

## What must not be translated

Peach is forensic software. Only the interface around the data gets
translated, never the data itself or anything an analyst types or exports.
The code takes care of most of this: these things never appear in the
`.ftl` files. Inside the text you do translate, keep these exactly as
written:

- **Command-line flags** like `--ephemeral-session`, `--add-source`
- **Search syntax** like `level=`, `tag=`, `after=`, `source_id=`
- **Format and source names** like EVTX, AUL, journald, logcat, syslog
- **Example values** like `+02:00`, `UTC`, `Europe/Berlin`
- **Placeholders** `{ $… }` (see above)

The English file's comments point these out where they occur.

Error *details*, the technical part after "Load failed:" for example, stay
in English on purpose. They are stored in the session's activity log, and
many come from libraries Peach can't translate. Only the surrounding text
is translated.

## Incomplete translations are fine

You don't have to translate everything at once. Any message missing from
your file is shown in English. When Peach gets new features, new English
messages appear, and a translation catches up whenever someone gets to it.

Settings shows each language with its coverage, for example
"Deutsch (de) — 87% translated".

## How to contribute

### Improve an existing language

1. Fork the repository and edit `i18n/<code>/peach.ftl`.
2. To translate a message, copy its line (and comment, if you like) from
   `i18n/en/peach.ftl` into your file, and translate the text.
3. Open a pull request.

### Add a new language

1. Create `i18n/<code>/peach.ftl`. `<code>` is the language's
   [ISO 639-1 code](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes),
   e.g. `fr` or `nl`. Add a region only if needed, e.g. `pt-BR`.
2. Start with `language-name`, the language's name in itself
   (`Français`, `Nederlands`). This is what Settings lists.
3. Translate as much as you like, then open a pull request.

No code change is needed: Peach finds every language directory
automatically.

**Script support:** Peach's interface font covers Latin, Greek and Cyrillic
scripts. Chinese, Japanese and Korean need an additional font, which Peach
doesn't ship yet. Right-to-left scripts (Arabic, Hebrew) aren't supported
by the UI toolkit.

## What CI checks

Every pull request runs a translation report. It appears as annotations on
your file in the PR's "Files changed" tab, and as a table on the CI run's
summary page.

**Errors** fail the check and must be fixed before merging:

| Error | Example | Why it matters |
|---|---|---|
| Syntax error | missing `=`, unclosed `{` | Broken entries are dropped when the file loads |
| Unknown id | `setings-title` (typo) | The text would never be shown |
| Duplicate id | the same id twice | Only one of the two would be used |
| Placeholder mismatch | `{ $cuont }` instead of `{ $count }`, or a placeholder left out | A number or path would go missing from the text |

A language whose file has errors can't be selected in Peach.

**Warnings** are informational only: the list of messages not translated yet.

If you do have Rust installed, you can run the same report locally:

```
cargo run --example i18n_check
```
