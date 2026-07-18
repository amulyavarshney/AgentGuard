package adapters

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
)

// PostgresAdapter classifies psql invocations and parses SQL for destructive actions.
type PostgresAdapter struct{}

// NewPostgresAdapter creates a PostgreSQL classifier.
func NewPostgresAdapter() *PostgresAdapter {
	return &PostgresAdapter{}
}

// Classify implements Adapter for psql shim proposals.
func (a *PostgresAdapter) Classify(_ context.Context, raw map[string]any) (model.ActionProposal, error) {
	tool, _ := raw["tool"].(string)
	argv := stringSlice(raw["argv"])
	sessionID, _ := raw["session_id"].(string)
	environment, _ := raw["environment"].(string)
	task, _ := raw["task"].(string)
	cwd, _ := raw["cwd"].(string)

	conn := extractPostgresConnection(argv)
	sqlText := extractPostgresSQL(argv)

	classification := classifySQL(sqlText)
	host := conn.Host
	if host == "" {
		host = envOrDefault("PGHOST", "localhost")
	}
	database := conn.Database
	if database == "" {
		database = envOrDefault("PGDATABASE", "postgres")
	}
	user := conn.User
	if user == "" {
		user = envOrDefault("PGUSER", os.Getenv("USER"))
	}

	resources := classification.resources
	if len(resources) == 0 && database != "" {
		resources = []string{database}
	}

	proposal := model.ActionProposal{
		ID:                   uuid.NewString(),
		SessionID:            sessionID,
		Timestamp:            time.Now().UTC(),
		IntentSummary:        task,
		ActionType:           "postgres",
		Command:              formatCommand(tool, argv),
		Environment:          environment,
		AffectedResources:    resources,
		EstimatedBlastRadius: classification.blastRadius,
		RawRequest: map[string]any{
			"tool":      tool,
			"argv":      argv,
			"cwd":       cwd,
			"sql":       sqlText,
			"host":      host,
			"database":  database,
			"user":      user,
			"port":      conn.Port,
			"action":    classification.action,
			"conn_uri":  conn.URI,
		},
	}
	if classification.destructive {
		proposal.RawRequest["destructive"] = true
	}
	return proposal, nil
}

type pgConnInfo struct {
	Host     string
	Port     string
	Database string
	User     string
	URI      string
}

type sqlClassification struct {
	action      string
	destructive bool
	resources   []string
	blastRadius int
}

func extractPostgresConnection(argv []string) pgConnInfo {
	var conn pgConnInfo
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "-h", arg == "--host":
			if i+1 < len(argv) {
				conn.Host = argv[i+1]
				i++
			}
		case strings.HasPrefix(arg, "-h"):
			conn.Host = strings.TrimPrefix(arg, "-h")
		case arg == "-p", arg == "--port":
			if i+1 < len(argv) {
				conn.Port = argv[i+1]
				i++
			}
		case arg == "-d", arg == "--dbname":
			if i+1 < len(argv) {
				conn.Database = argv[i+1]
				i++
			}
		case arg == "-U", arg == "--username":
			if i+1 < len(argv) {
				conn.User = argv[i+1]
				i++
			}
		case strings.HasPrefix(arg, "postgres://"), strings.HasPrefix(arg, "postgresql://"):
			conn.URI = arg
			conn.Host, conn.Database, conn.User = parsePostgresURI(arg)
		case !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "postgres") && conn.Database == "" && !isPsqlMetaFlag(arg):
			conn.Database = arg
		}
	}
	if conn.URI == "" && os.Getenv("DATABASE_URL") != "" {
		conn.URI = os.Getenv("DATABASE_URL")
		conn.Host, conn.Database, conn.User = parsePostgresURI(conn.URI)
	}
	return conn
}

func isPsqlMetaFlag(arg string) bool {
	switch arg {
	case "-c", "-f", "--file", "-e", "--echo-queries", "--single-transaction", "--command":
		return true
	default:
		return false
	}
}

func parsePostgresURI(uri string) (host, database, user string) {
	// postgres://user:pass@host:5432/dbname
	re := regexp.MustCompile(`^postgres(?:ql)?://(?:([^:@/]+)(?::[^@]*)?@)?([^:/]+)(?::(\d+))?/([^?]+)`)
	m := re.FindStringSubmatch(uri)
	if len(m) < 5 {
		return "", "", ""
	}
	return m[2], m[4], m[1]
}

func extractPostgresSQL(argv []string) string {
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-c", "--command":
			if i+1 < len(argv) {
				return argv[i+1]
			}
		case "-f", "--file":
			if i+1 < len(argv) {
				return "-- file:" + argv[i+1]
			}
		}
	}
	return ""
}

var (
	reDrop    = regexp.MustCompile(`(?is)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\s+(?:IF\s+EXISTS\s+)?([^\s;]+)`)
	reTruncate = regexp.MustCompile(`(?is)\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?([^\s;]+)`)
	reDelete  = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+([^\s;]+)([\s\S]*)`)
)

func classifySQL(sql string) sqlClassification {
	if sql == "" {
		return sqlClassification{action: "connect"}
	}
	normalized := stripSQLComments(sql)
	upper := strings.ToUpper(normalized)

	if m := reDrop.FindStringSubmatch(normalized); len(m) >= 2 {
		return sqlClassification{
			action:      "drop",
			destructive: true,
			resources:   []string{cleanIdent(m[1])},
			blastRadius: 1,
		}
	}
	if m := reTruncate.FindStringSubmatch(normalized); len(m) >= 2 {
		return sqlClassification{
			action:      "truncate",
			destructive: true,
			resources:   []string{cleanIdent(m[1])},
			blastRadius: 1000, // unknown row count; assume table-level
		}
	}
	if m := reDelete.FindStringSubmatch(normalized); len(m) >= 3 {
		table := cleanIdent(m[1])
		rest := strings.ToUpper(m[2])
		if !strings.Contains(rest, " WHERE ") {
			return sqlClassification{
				action:      "bulk_delete",
				destructive: true,
				resources:   []string{table},
				blastRadius: 10000,
			}
		}
		if !strings.Contains(rest, " LIMIT ") {
			return sqlClassification{
				action:      "bulk_delete",
				destructive: true,
				resources:   []string{table},
				blastRadius: 500,
			}
		}
		return sqlClassification{action: "delete", resources: []string{table}}
	}
	if strings.HasPrefix(strings.TrimSpace(upper), "SELECT") {
		return sqlClassification{action: "select"}
	}
	if strings.HasPrefix(strings.TrimSpace(upper), "INSERT") ||
		strings.HasPrefix(strings.TrimSpace(upper), "UPDATE") {
		return sqlClassification{action: strings.ToLower(strings.Fields(upper)[0])}
	}
	return sqlClassification{action: "query"}
}

func stripSQLComments(sql string) string {
	lines := strings.Split(sql, "\n")
	var out []string
	for _, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func cleanIdent(s string) string {
	s = strings.Trim(s, `"`)
	s = strings.Trim(s, `'`)
	s = strings.Trim(s, ";")
	return s
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
