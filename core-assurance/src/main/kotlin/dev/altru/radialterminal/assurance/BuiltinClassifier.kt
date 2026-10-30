package dev.altru.radialterminal.assurance

import java.time.Instant

/**
 * Conservative, local-only classifier.
 *
 * This is not a shell semantic prover. It parses the command line into simple
 * commands (splitting on `;`, `&&`, `||`, `|`, `&`, newlines, and descending
 * into `$(...)`, backticks and `sh -c '...'`), strips wrappers such as `sudo`,
 * `env`, `xargs` and `timeout`, and then classifies each program.
 *
 * Default posture: a command is ALLOWED only when every simple command in it is
 * a recognised read-only command with no output redirection. Anything the
 * classifier does not recognise goes to REVIEW. Known destructive operations
 * are BLOCKED.
 */
class BuiltinClassifier : AssuranceProvider {
    override val id: String = "builtin-static"
    override val version: String = "0.2.0"

    override fun evaluate(request: PreflightRequest): AssuranceDecision {
        val findings = mutableListOf<Finding>()
        if (request.command.isBlank()) {
            return AssuranceDecision(Disposition.ALLOW, id, version, emptyList(), Instant.now())
        }
        val parsed = ShellParser.parse(request.command)
        if (!parsed.complete) {
            findings += Finding(FindingKind.PARSE_UNCERTAIN, "Command line could not be parsed with confidence (unbalanced quotes or substitution).")
        }
        if (parsed.pipesRemoteContentIntoInterpreter) {
            findings += Finding(FindingKind.REMOTE_CODE_EXECUTION, "Downloaded content is piped into an interpreter.")
        }
        val firstWord = parsed.commands.firstOrNull()?.words?.firstOrNull()?.lowercase()
        val sqlContext = firstWord in SQL_KEYWORDS ||
            parsed.commands.any { c -> c.words.any { w -> w.substringAfterLast('/') in DB_CLIENTS } }
        if (sqlContext) SQL_DESTRUCTIVE.find(request.command)?.let {
            findings += Finding(FindingKind.DATABASE_MUTATION, "Potentially destructive database statement: ${it.value.trim()}.")
        }

        var everythingReadOnly = parsed.complete && parsed.commands.isNotEmpty()
        for (command in parsed.commands) {
            val result = classify(command)
            findings += result.findings
            if (!result.readOnly) everythingReadOnly = false
        }

        val disposition = when {
            findings.any { it.kind in BLOCKING } -> Disposition.BLOCK
            findings.isNotEmpty() -> Disposition.REVIEW
            everythingReadOnly -> Disposition.ALLOW
            else -> Disposition.REVIEW
        }
        val reported = if (disposition == Disposition.REVIEW && findings.isEmpty()) {
            listOf(Finding(FindingKind.UNRECOGNISED_COMMAND, "Command is not on the read-only list; review before running."))
        } else {
            findings.distinctBy { it.kind to it.summary }
        }

        return AssuranceDecision(
            disposition = disposition,
            provider = id,
            providerVersion = version,
            findings = reported,
            decidedAt = Instant.now(),
        )
    }

    private class Classified(val readOnly: Boolean, val findings: List<Finding>)

    private fun classify(command: SimpleCommand): Classified {
        val findings = mutableListOf<Finding>()
        var words = command.words
        var privileged = false

        // Strip wrappers that run another program, remembering privilege changes.
        loop@ while (words.isNotEmpty()) {
            val head = programName(words[0])
            when {
                ASSIGNMENT.matches(words[0]) -> words = words.drop(1)
                head in PRIVILEGE_WRAPPERS -> {
                    privileged = true
                    words = dropOptions(words.drop(1), optionsWithValue = setOf("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"))
                }
                head == "env" -> words = dropOptions(words.drop(1), setOf("-u", "-C", "-S")).dropWhile { ASSIGNMENT.matches(it) }
                head in SIMPLE_WRAPPERS -> words = dropOptions(words.drop(1), setOf("-n", "-c", "-p", "-i", "-o", "-e", "-s", "-k", "-L", "-I", "-P", "-d", "-E", "-a"))
                head == "timeout" -> words = dropOptions(words.drop(1), setOf("-s", "-k", "--signal", "--kill-after")).drop(1)
                else -> break@loop
            }
        }
        if (privileged) {
            findings += Finding(FindingKind.PRIVILEGE_ESCALATION, "Command requests elevated execution authority.")
        }
        if (words.isEmpty()) return Classified(readOnly = !privileged, findings = findings)

        val program = programName(words[0])
        val args = words.drop(1)
        val flags = shortFlags(args)
        fun has(vararg long: String) = args.any { it in long }

        command.redirectTargets.forEach { target ->
            when {
                BLOCK_DEVICE.matches(target) -> findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "Output is redirected onto a block device ($target).")
                target != "/dev/null" && !target.startsWith("&") -> findings += Finding(FindingKind.FILE_WRITE, "Output is written to $target.")
            }
        }

        when (program) {
            "rm" -> if ('r' in flags || 'R' in flags || has("--recursive")) {
                findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "Recursive removal detected.")
            } else {
                findings += Finding(FindingKind.FILE_WRITE, "File removal detected.")
            }
            "rmdir", "unlink", "mv", "cp", "ln", "touch", "mkdir", "tee", "install", "rsync" ->
                findings += Finding(FindingKind.FILE_WRITE, "Filesystem contents may change ($program).")
            "shred", "wipefs", "blkdiscard", "sgdisk", "sfdisk", "fdisk", "parted", "mkswap" ->
                findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "Disk or partition contents may be destroyed ($program).")
            "dd" -> if (args.any { it.startsWith("of=") }) {
                val target = args.first { it.startsWith("of=") }.removePrefix("of=")
                findings += if (BLOCK_DEVICE.matches(target)) {
                    Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "dd writes directly to a block device ($target).")
                } else {
                    Finding(FindingKind.FILE_WRITE, "dd writes to $target.")
                }
            }
            "truncate" -> findings += Finding(FindingKind.FILE_WRITE, "File contents may be truncated.")
            "find" -> if (has("-delete") || args.windowed(2).any { (a, b) -> a in setOf("-exec", "-execdir", "-ok") && programName(b) in setOf("rm", "shred", "unlink") }) {
                findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "find deletes matching files.")
            } else if (has("-exec", "-execdir", "-ok", "-fprint", "-fprintf", "-fls")) {
                findings += Finding(FindingKind.UNKNOWN_HIGH_IMPACT, "find runs or writes on each match.")
            }
            "sed" -> if ('i' in flags || args.any { it.startsWith("--in-place") }) {
                findings += Finding(FindingKind.FILE_WRITE, "sed edits files in place.")
            }
            "shutdown", "reboot", "poweroff", "halt" ->
                findings += Finding(FindingKind.POWER_STATE_CHANGE, "Host power state will change.")
            "init", "telinit" -> if (args.firstOrNull() in setOf("0", "6")) {
                findings += Finding(FindingKind.POWER_STATE_CHANGE, "Host power state will change.")
            }
            "systemctl" -> when (args.firstOrNull { !it.startsWith("-") }) {
                "status", "show", "cat", "list-units", "list-unit-files", "list-timers", "is-active", "is-enabled", "is-failed", null -> Unit
                "reboot", "poweroff", "halt", "kexec", "suspend", "hibernate" ->
                    findings += Finding(FindingKind.POWER_STATE_CHANGE, "Host power state will change.")
                else -> findings += Finding(FindingKind.SERVICE_STATE_CHANGE, "Service state mutation detected.")
            }
            "service" -> if (args.getOrNull(1) != "status") {
                findings += Finding(FindingKind.SERVICE_STATE_CHANGE, "Service state mutation detected.")
            }
            "kill", "pkill", "killall" -> findings += Finding(FindingKind.SERVICE_STATE_CHANGE, "Processes will be signalled.")
            "apt", "apt-get", "dnf", "yum", "zypper", "apk", "snap", "pacman", "brew", "pip", "pip3", "npm", "gem" -> {
                val sub = args.firstOrNull { !it.startsWith("-") }
                val removal = sub in setOf("remove", "purge", "autoremove", "erase", "del", "uninstall") ||
                    (program == "pacman" && args.any { it.startsWith("-R") })
                val readOnlySub = sub in setOf("list", "search", "show", "info", "policy", "--version", "outdated", "freeze", "view", "ls")
                when {
                    removal -> findings += Finding(FindingKind.PACKAGE_STATE_CHANGE, "Package removal detected.")
                    !readOnlySub -> findings += Finding(FindingKind.PACKAGE_STATE_CHANGE, "Package state may change ($program ${sub ?: ""}).")
                }
            }
            "iptables", "ip6tables", "nft", "ufw", "firewall-cmd" ->
                if (!(program == "iptables" && ('L' in flags || has("--list")))) {
                    findings += Finding(FindingKind.NETWORK_POLICY_CHANGE, "Network policy mutation may occur.")
                }
            "ip" -> if (args.any { it in setOf("add", "del", "delete", "set", "flush", "change", "replace") }) {
                findings += Finding(FindingKind.NETWORK_POLICY_CHANGE, "Network configuration change detected.")
            }
            "chmod", "chown", "chgrp", "setfacl", "chattr", "useradd", "userdel", "usermod",
            "groupadd", "groupdel", "groupmod", "passwd", "chpasswd", "visudo" ->
                findings += Finding(FindingKind.IDENTITY_OR_PERMISSION_CHANGE, "Identity or permission state may change.")
            "docker", "podman" -> {
                val sub = args.filterNot { it.startsWith("-") }
                if (sub.take(2) == listOf("system", "prune") || sub.firstOrNull() in setOf("rm", "rmi", "kill", "stop", "prune") ||
                    (sub.size >= 2 && sub[1] in setOf("rm", "prune"))
                ) {
                    findings += Finding(FindingKind.CONTAINER_OR_CLUSTER_MUTATION, "Container state mutation detected.")
                } else if (sub.firstOrNull() !in DOCKER_READ_ONLY) {
                    findings += Finding(FindingKind.CONTAINER_OR_CLUSTER_MUTATION, "Container state may change (docker ${sub.firstOrNull() ?: ""}).")
                }
            }
            "kubectl", "helm", "terraform", "tofu" -> {
                val sub = args.firstOrNull { !it.startsWith("-") }
                if (sub !in CLUSTER_READ_ONLY) {
                    findings += Finding(FindingKind.CONTAINER_OR_CLUSTER_MUTATION, "Cluster or infrastructure state may change ($program ${sub ?: ""}).")
                }
            }
            "git" -> {
                val sub = args.firstOrNull { !it.startsWith("-") }
                when {
                    sub == "push" && (has("--force", "--force-with-lease", "--mirror", "--delete") || 'f' in flags || args.any { it.startsWith("--force") || it.startsWith("+") }) ->
                        findings += Finding(FindingKind.FORCE_OPERATION, "Force or destructive push detected.")
                    sub == "reset" && has("--hard") -> findings += Finding(FindingKind.FORCE_OPERATION, "Hard reset discards local changes.")
                    sub == "clean" && ('f' in flags || has("--force")) -> findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "git clean deletes untracked files.")
                    sub !in GIT_READ_ONLY -> findings += Finding(FindingKind.UNKNOWN_HIGH_IMPACT, "Repository state may change (git ${sub ?: ""}).")
                }
            }
            in INTERPRETERS -> if (args.isEmpty() || args.any { it == "-c" || it == "-e" || it == "-" }) {
                // inline code was already parsed for nested commands when it was a shell
                findings += Finding(FindingKind.UNKNOWN_HIGH_IMPACT, "Interpreter runs code that is not inspected.")
            } else {
                findings += Finding(FindingKind.UNKNOWN_HIGH_IMPACT, "Interpreter runs a script that is not inspected.")
            }
            "curl" -> if (args.any { a -> CURL_WRITES.any { a == it || (it.startsWith("--") && a.startsWith("$it=")) } } ||
                args.any { it.startsWith("-") && !it.startsWith("--") && it.drop(1).any { ch -> ch in "XdFToO" } }
            ) {
                findings += Finding(FindingKind.UNKNOWN_HIGH_IMPACT, "curl may send data, change remote state, or write files.")
            }
            "wget" -> {
                val toStdout = args.any { it == "--spider" || it == "-O-" || it == "-qO-" || it == "--output-document=-" } ||
                    args.windowed(2).any { (a, b) -> (a == "-O" || a == "--output-document") && b == "-" }
                val sends = args.any { it.startsWith("--post") || it.startsWith("--method") || it.startsWith("--body") }
                if (!toStdout || sends) findings += Finding(FindingKind.FILE_WRITE, "wget writes downloaded content to disk or sends data.")
            }
            "date" -> if (args.any { it == "-s" || it.startsWith("--set") }) {
                findings += Finding(FindingKind.UNKNOWN_HIGH_IMPACT, "System clock will be changed.")
            }
            "journalctl" -> if (args.any { it.startsWith("--vacuum") || it == "--rotate" || it == "--flush" || it == "--relinquish-var" }) {
                findings += Finding(FindingKind.FILE_WRITE, "Journal files will be rotated or deleted.")
            }
            in MKFS -> findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "A filesystem will be created, destroying existing data.")
        }
        if (program.startsWith("mkfs")) {
            findings += Finding(FindingKind.DESTRUCTIVE_FILESYSTEM, "A filesystem will be created, destroying existing data.")
        }

        val readOnly = findings.isEmpty() && !privileged && program in READ_ONLY
        return Classified(readOnly, findings)
    }

    private fun programName(word: String): String = word.removePrefix("\\").substringAfterLast('/')

    private fun shortFlags(args: List<String>): Set<Char> =
        args.filter { it.startsWith("-") && !it.startsWith("--") && it.length > 1 }
            .flatMap { it.drop(1).toList() }
            .toSet()

    /** Drops leading options (and the values of options that take one), plus a `--` terminator. */
    private fun dropOptions(words: List<String>, optionsWithValue: Set<String>): List<String> {
        var i = 0
        while (i < words.size && words[i].startsWith("-")) {
            if (words[i] == "--") return words.drop(i + 1)
            if (words[i] in optionsWithValue) i++
            i++
        }
        return words.drop(i)
    }

    private companion object {
        val BLOCKING = setOf(FindingKind.DESTRUCTIVE_FILESYSTEM, FindingKind.DATABASE_MUTATION)
        val ASSIGNMENT = Regex("""^[A-Za-z_][A-Za-z0-9_]*=.*""", RegexOption.DOT_MATCHES_ALL)
        val BLOCK_DEVICE = Regex("""^/dev/(sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(p\d+)?|mmcblk\d+(p\d+)?|md\d+|dm-\d+|mapper/.+|disk/.+)$""")
        val SQL_KEYWORDS = setOf("drop", "truncate", "delete", "alter")
        val DB_CLIENTS = setOf("psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "clickhouse-client", "cqlsh", "redis-cli", "duckdb")
        val CURL_WRITES = setOf("--request", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--form", "--upload-file", "--output", "--remote-name", "--remote-name-all", "--delete")
        val SQL_DESTRUCTIVE = Regex("""\b(drop\s+(database|schema|table|user|role)|truncate\s+(table\s+)?\w|delete\s+from\s+\w+\s*(;|$|["']))""", RegexOption.IGNORE_CASE)
        val PRIVILEGE_WRAPPERS = setOf("sudo", "doas", "su", "pkexec", "runuser", "run0")
        val SIMPLE_WRAPPERS = setOf("nice", "nohup", "time", "command", "builtin", "exec", "stdbuf", "ionice", "xargs", "watch", "chronic", "flock")
        val INTERPRETERS = setOf("sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node", "php", "lua", "eval", "source", ".")
        val MKFS = setOf("mkfs", "mke2fs", "mkntfs", "mkdosfs")
        val DOCKER_READ_ONLY = setOf("ps", "images", "logs", "inspect", "info", "version", "stats", "top", "port", "history", "events", "diff", null)
        val CLUSTER_READ_ONLY = setOf("get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions",
            "cluster-info", "config", "auth", "status", "list", "history", "show", "plan", "validate", "fmt", "output", "graph", "providers", null)
        val GIT_READ_ONLY = setOf("status", "log", "diff", "show", "branch", "tag", "remote", "fetch", "blame", "describe",
            "rev-parse", "ls-files", "shortlog", "reflog", "grep", "config", "stash", null)
        val READ_ONLY = setOf(
            "ls", "ll", "la", "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "find", "fd", "locate",
            "pwd", "cd", "whoami", "id", "groups", "who", "w", "last", "uptime", "date", "cal", "uname", "hostname",
            "df", "du", "free", "vmstat", "iostat", "lsblk", "blkid", "lscpu", "lsmem", "lsusb", "lspci", "lsof",
            "ps", "pgrep", "top", "htop", "btop", "pstree", "journalctl", "dmesg", "ss", "netstat", "ping", "traceroute",
            "dig", "nslookup", "host", "curl", "wget", "echo", "printf", "true", "false", "test", "[", "which", "type",
            "whereis", "file", "stat", "wc", "sort", "uniq", "cut", "tr", "column", "diff", "cmp", "md5sum", "sha1sum",
            "sha256sum", "sha512sum", "base64", "jq", "yq", "sed", "env", "printenv", "history", "man", "help", "tree",
            "readlink", "realpath", "basename", "dirname", "nproc", "getent", "systemctl", "service", "docker", "podman",
            "kubectl", "helm", "terraform", "tofu", "git", "apt", "apt-get", "dnf", "yum", "pip", "pip3", "npm", "iptables",
            "ip", "clear", "exit", "tmux", "screen",
        )
    }
}

/** One program invocation after splitting a command line. */
internal data class SimpleCommand(val words: List<String>, val redirectTargets: List<String>)

internal data class ParsedCommandLine(
    val commands: List<SimpleCommand>,
    val complete: Boolean,
    val pipesRemoteContentIntoInterpreter: Boolean,
)

/**
 * Minimal POSIX-ish shell lexer: quotes, backslash escapes, command separators,
 * redirections and command substitution. It never executes anything and errs
 * on the side of reporting `complete = false`.
 */
internal object ShellParser {
    private val SHELLS = setOf("sh", "bash", "zsh", "dash", "ksh")
    private val FETCHERS = setOf("curl", "wget", "fetch", "aria2c")
    private val INTERPRETERS = SHELLS + setOf("python", "python3", "perl", "ruby", "node", "php")

    fun parse(input: String, depth: Int = 0): ParsedCommandLine {
        val commands = mutableListOf<SimpleCommand>()
        var complete = true
        var remotePipe = false
        if (depth > 8) return ParsedCommandLine(emptyList(), complete = false, pipesRemoteContentIntoInterpreter = false)

        val words = mutableListOf<String>()
        val redirects = mutableListOf<String>()
        val current = StringBuilder()
        var inWord = false
        var pendingRedirect = false
        var previousStageFetches = false
        var i = 0

        fun endWord() {
            if (!inWord) return
            val word = current.toString()
            if (pendingRedirect) {
                redirects += word
                pendingRedirect = false
            } else {
                words += word
            }
            current.clear()
            inWord = false
        }

        fun endCommand(pipeFollows: Boolean) {
            endWord()
            if (pendingRedirect) complete = false
            if (words.isNotEmpty()) {
                val program = words[0].substringAfterLast('/')
                if (previousStageFetches && program in INTERPRETERS) remotePipe = true
                commands += SimpleCommand(words.toList(), redirects.toList())
                // descend into `sh -c '...'`
                val c = words.indexOf("-c")
                if (program in SHELLS && c >= 0 && c + 1 < words.size) {
                    val nested = parse(words[c + 1], depth + 1)
                    commands += nested.commands
                    complete = complete && nested.complete
                    remotePipe = remotePipe || nested.pipesRemoteContentIntoInterpreter
                }
                previousStageFetches = pipeFollows && program in FETCHERS
            } else if (pipeFollows) {
                previousStageFetches = false
            }
            words.clear()
            redirects.clear()
        }

        fun substitution(close: Char, open: Char?): String? {
            // returns the substitution body and advances i past the closing char
            val body = StringBuilder()
            var level = 1
            var quote: Char? = null
            i++
            while (i < input.length) {
                val ch = input[i]
                when {
                    quote != null -> if (ch == quote) quote = null
                    ch == '\'' || ch == '"' -> quote = ch
                    open != null && ch == open -> level++
                    ch == close -> { level--; if (level == 0) return body.toString() }
                }
                body.append(ch)
                i++
            }
            return null
        }

        while (i < input.length) {
            val ch = input[i]
            when {
                ch == '\\' && i + 1 < input.length -> {
                    if (input[i + 1] == '\n') { i += 2; continue }
                    current.append(input[i + 1]); inWord = true; i += 2; continue
                }
                ch == '\'' -> {
                    val end = input.indexOf('\'', i + 1)
                    if (end < 0) { complete = false; current.append(input.substring(i + 1)); inWord = true; i = input.length; continue }
                    current.append(input, i + 1, end); inWord = true; i = end + 1; continue
                }
                ch == '"' -> {
                    var j = i + 1
                    val sb = StringBuilder()
                    var closed = false
                    while (j < input.length) {
                        val c = input[j]
                        if (c == '\\' && j + 1 < input.length) { sb.append(input[j + 1]); j += 2; continue }
                        if (c == '"') { closed = true; break }
                        if (c == '$' && j + 1 < input.length && input[j + 1] == '(') {
                            val saved = i
                            i = j + 1
                            val body = substitution(')', '(')
                            if (body == null) { complete = false } else {
                                val nested = parse(body, depth + 1)
                                commands += nested.commands
                                complete = complete && nested.complete
                                remotePipe = remotePipe || nested.pipesRemoteContentIntoInterpreter
                            }
                            j = i + 1
                            i = saved
                            continue
                        }
                        sb.append(c); j++
                    }
                    if (!closed) complete = false
                    current.append(sb); inWord = true; i = j + 1; continue
                }
                ch == '$' && i + 1 < input.length && input[i + 1] == '(' -> {
                    i++
                    val body = substitution(')', '(')
                    if (body == null) complete = false else {
                        val nested = parse(body, depth + 1)
                        commands += nested.commands
                        complete = complete && nested.complete
                        remotePipe = remotePipe || nested.pipesRemoteContentIntoInterpreter
                    }
                    current.append("\$SUBST"); inWord = true; i++; continue
                }
                ch == '`' -> {
                    val body = substitution('`', null)
                    if (body == null) complete = false else {
                        val nested = parse(body, depth + 1)
                        commands += nested.commands
                        complete = complete && nested.complete
                        remotePipe = remotePipe || nested.pipesRemoteContentIntoInterpreter
                    }
                    current.append("\$SUBST"); inWord = true; i++; continue
                }
                ch == '|' -> {
                    val pipe = !(i + 1 < input.length && input[i + 1] == '|')
                    endCommand(pipeFollows = pipe)
                    i += if (pipe) 1 else 2
                    if (pipe && i < input.length && input[i] == '&') i++
                    continue
                }
                ch == ';' || ch == '\n' -> { endCommand(false); i++; continue }
                ch == '&' -> {
                    if (i + 1 < input.length && input[i + 1] == '>') { // &> file
                        endWord(); pendingRedirect = true; i += 2
                        if (i < input.length && input[i] == '>') i++
                        continue
                    }
                    endCommand(false)
                    i += if (i + 1 < input.length && input[i + 1] == '&') 2 else 1
                    continue
                }
                ch == '>' || ch == '<' -> {
                    // fd prefix like 2> is part of the redirect, not a word
                    if (inWord && current.all { it.isDigit() }) { current.clear(); inWord = false } else endWord()
                    val input_ = ch == '<'
                    i++
                    if (i < input.length && (input[i] == '>' || input[i] == '|')) i++
                    if (i < input.length && input[i] == '&') { // >&2, 2>&1
                        i++
                        while (i < input.length && (input[i].isDigit() || input[i] == '-')) i++
                        continue
                    }
                    if (!input_) pendingRedirect = true else {
                        // input redirection: consume and ignore the source word
                        while (i < input.length && input[i] == ' ') i++
                        while (i < input.length && !input[i].isWhitespace() && input[i] !in ";|&<>") i++
                    }
                    continue
                }
                ch.isWhitespace() -> { endWord(); i++; continue }
                ch == '#' && !inWord -> { // comment to end of line
                    while (i < input.length && input[i] != '\n') i++
                    continue
                }
                else -> { current.append(ch); inWord = true; i++; continue }
            }
        }
        endCommand(false)
        return ParsedCommandLine(commands, complete, remotePipe)
    }
}
