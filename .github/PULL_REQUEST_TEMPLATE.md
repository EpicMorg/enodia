## What this changes

<!-- One or two sentences. -->

## Type

- [ ] New product probe
- [ ] Bug fix
- [ ] Feature
- [ ] Docs
- [ ] Refactor / chore

## If this adds a probe

- [ ] File is `internal/probe/<product>.go`
- [ ] Registered in `internal/probe/registry.go`
- [ ] Recorded vendor response in `internal/probe/testdata/`
- [ ] Test parses that file and asserts the version
- [ ] `Meta()` declares product, default resolver, and auth requirements
- [ ] Recorded response contains no hostnames, tokens, or internal data

Product and version tested against:

## Checklist

- [ ] `gofmt` clean, `golangci-lint run` clean
- [ ] `go test ./...` passes
- [ ] No credentials in code, tests, logs, or fixtures
- [ ] Config or inventory schema unchanged, or `schemaVersion` bumped
