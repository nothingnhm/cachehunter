# nuclei-templates/

Drop optional local Nuclei templates here. They are only run when you do
**not** pass `-t <template.yaml>` on the command line, and this directory
is **not guaranteed to contain cache-poisoning-specific checks** — verify
what's in here before relying on it.

To run a specific template of your own instead, use:

```bash
./cachehunter.sh -u https://target.example.com -t ./my-cache-template.yaml

### For runing multiple template
# repeat the flag
./cachehunter.sh -u https://target.example.com -t tmpl1.yaml -t tmpl2.yaml -t tmpl3.yaml

# or comma-separate in one flag
./cachehunter.sh -u https://target.example.com -t tmpl1.yaml,tmpl2.yaml,tmpl3.yaml
```

The supplied template is executed exactly as provided and is never
rewritten or replaced by CacheHunter.
