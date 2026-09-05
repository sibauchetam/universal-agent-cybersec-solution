You are working in `/app/target_home/` — a dumped home directory of a developer
account that leaked credentials all over the place (T1552-style). A flag was
split into 3 parts and stashed among the credential files.

Find all 3 parts and write the assembled flag to:

`/app/recovered_flag.txt`

The file must contain EXACTLY one line: `FLAG{part1_part2_part3}` where
part1/part2/part3 are the literal parts you recover. No extra whitespace.

Hints:
- One part hides in a comment of a configuration file with cloud secrets.
- One part is base64-encoded inside shell history.
- One part is in an SSH metadata comment.
Do not modify anything under `/app/target_home/`.
