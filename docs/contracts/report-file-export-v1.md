# Supervised local report file export contract v1

`report-file-export-v1.schema.json` records one immutable local export receipt for an
exact approved findings or No Findings artifact. The core reloads the approval and
artifact in one transaction, verifies both content hashes, and accepts only one of the
four bounded report formats.

The authenticated human explicitly confirms restricted-data export and selects an
existing directory. The core derives the leaf filename from the report UUID and format,
never accepts a caller-controlled filename, refuses overwrite, writes a same-directory
temporary file, synchronizes it, and publishes it exclusively. Audit and receipt data
contain the filename and digest but not the destination path or report body.

Migration `0029_report_file_exports.sql` is additive and makes completed receipts
immutable. Repeating an identical export returns its receipt only while the destination
still contains the exact approved bytes; missing or changed output denies. Rollback may
leave the unused receipt table in place. This capability writes one local file and does
not upload, submit, email, or otherwise create network authority.
