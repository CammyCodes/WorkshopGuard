Drop your own YARA rules (`*.yar`) here. They're loaded next to the bundled rules on start-up.

Add `severity` (`info`, `low`, `medium`, `high`, `critical`) and `description` to each rule's `meta`. A `critical`
match marks the item as malicious. To rescan everything with new rules: `docker compose run --rm guard rescan --all`.
