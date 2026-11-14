package guard

import "regexp"

// risky are shell commands that print secrets wholesale, with what to do
// instead. Each is matched at the start of a command: the whole line, or
// after ;, &, |, ( or a newline. Only these few: a command that merely uses
// a secret, or prints one variable that is not secret-looking, goes ahead.
var risky = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`\btouchenv\b[^;&|\n]*?\sget\b`),
		"touchenv get prints a secret, so it would be in this chat; use touchenv run --intent \"<why>\" NAME -- <command>, which hands it to the command only"},
	{regexp.MustCompile(`(?:^|[;&|(\n])\s*(?:env|printenv|export|set)\s*(?:$|[;&|)>\n])`),
		"it prints every environment variable, secrets included; print the one you need (printenv PATH), or test whether one is set ([ -n \"$NAME\" ])"},
	{regexp.MustCompile(`(?i)(?:^|[;&|(\n])\s*printenv\s+[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL)`),
		"it prints a secret; test whether it is set instead ([ -n \"$NAME\" ] && echo set)"},
	{regexp.MustCompile(`(?:^|[;&|(\n])\s*(?:cat|head|tail|less|more|bat|nl|strings|grep|rg)\b[^;&|\n]*?(?:^|[\s/'"])\.env(?:\.(?:local|development|dev|production|prod|staging|test))?(?:$|[\s'";&|)])`),
		"it prints a .env file's secrets; list its variable names without values instead: sed 's/=.*//' .env"},
	{regexp.MustCompile(`\bsecurity\s+find-(?:generic|internet)-password\b[^;&|\n]*\s-w\b`),
		"it prints a password from the Keychain"},
	{regexp.MustCompile(`(?:^|[;&|(\n])\s*(?:op\s+read|secret-tool\s+lookup|pass\s+show|gh\s+auth\s+token|aws\s+configure\s+get\s+aws_secret_access_key)\b`),
		"it prints a secret from a password manager or credential store; pass it to the command that needs it instead (op run, or touchenv run)"},
}

// Risky reports whether a shell command an AI assistant is about to run
// would print secrets wholesale, and why.
func Risky(command string) (string, bool) {
	for _, r := range risky {
		if r.re.MatchString(command) {
			return "BorderCheck refused this command: " + r.why + ". (bordercheck guard: to allow it, the person can run it in their own terminal.)", true
		}
	}
	return "", false
}
