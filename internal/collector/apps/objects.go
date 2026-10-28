package apps

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// Kinds of database objects. Code kept in the database survives a cleanup of the files: a
// trigger rewrites orders, an event runs on a schedule, an integration or an admin token is a way
// back in after the passwords change, a layout update or an email template runs PHP through
// Magento's template engine.
const (
	ObjectTrigger       = "trigger"
	ObjectProcedure     = "procedure"
	ObjectFunction      = "function"
	ObjectEvent         = "event"
	ObjectIntegration   = "integration"
	ObjectAdminToken    = "admin_token"
	ObjectLayoutUpdate  = "layout_update"
	ObjectEmailTemplate = "email_template"
	ObjectCustomer      = "customer"
)

// DBObject is an object of the application's database. Name and Target are written by whoever
// created it. Hash covers what it does (computed by the database server, so its body never
// leaves it); Markers name the dangerous constructs found in it. The bodies themselves, token
// values and customers' names are never collected.
type DBObject struct {
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Target  string   `json:"target,omitempty"`
	Hash    string   `json:"hash,omitempty"`
	Created string   `json:"created,omitempty"`
	Definer string   `json:"definer,omitempty"`
	Markers []string `json:"markers,omitempty"`
}

// codeMarkers are the constructs that run code from a layout update, an email template or a
// field rendered by one: PHP tags, calls that execute or decode, and the template filter
// callbacks TrojanOrder-style attacks chain to reach them.
var codeMarkers = []string{
	"<?php", "<?=", "system(", "exec(", "passthru(", "shell_exec(", "popen(", "proc_open(", "eval(", "assert(",
	"base64_decode(", "gzinflate(", "call_user_func", "gettemplatefilter", "addafterfiltercallback", "framework\\filesystem",
}

// templateMarkers are what a customer's name never holds unless someone aims it at a template.
var templateMarkers = []string{"{{", "}}", "<?", "<script", "${"}

func markers(body string, list []string) []string {
	lower := strings.ToLower(body)
	var out []string
	for _, m := range list {
		if strings.Contains(lower, m) {
			out = append(out, m)
		}
	}
	return out
}

// objectQuery is one bounded listing of objects of a kind.
type objectQuery struct {
	kind, sql string
	object    func(r map[string]string) DBObject
}

func limit(sql string) string { return sql + " LIMIT " + fmt.Sprint(maxRows) }

// schemaQueries list the programmable objects of the application's own schema, on any
// framework. Without the privilege to read a routine's body MySQL returns NULL, and the hash
// then only follows its name and definer.
var schemaQueries = []objectQuery{
	{ObjectTrigger, limit(`SELECT TRIGGER_NAME AS name, EVENT_OBJECT_TABLE AS target, CONCAT(ACTION_TIMING, ' ', EVENT_MANIPULATION) AS what,
		DEFINER AS definer, SHA2(ACTION_STATEMENT, 256) AS hash, CREATED AS created
		FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() ORDER BY TRIGGER_NAME`),
		func(r map[string]string) DBObject {
			return DBObject{ID: r["name"], Name: r["name"], Target: r["target"] + " (" + r["what"] + ")", Hash: r["hash"], Created: r["created"], Definer: r["definer"]}
		}},
	{"routine", limit(`SELECT ROUTINE_NAME AS name, ROUTINE_TYPE AS what, DEFINER AS definer,
		SHA2(COALESCE(ROUTINE_DEFINITION, ''), 256) AS hash, CREATED AS created
		FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() ORDER BY ROUTINE_NAME`),
		func(r map[string]string) DBObject {
			kind := ObjectProcedure
			if r["what"] == "FUNCTION" {
				kind = ObjectFunction
			}
			return DBObject{Kind: kind, ID: r["name"], Name: r["name"], Hash: r["hash"], Created: r["created"], Definer: r["definer"]}
		}},
	{ObjectEvent, limit(`SELECT EVENT_NAME AS name, STATUS AS what, DEFINER AS definer, SHA2(EVENT_DEFINITION, 256) AS hash, CREATED AS created
		FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE() ORDER BY EVENT_NAME`),
		func(r map[string]string) DBObject {
			return DBObject{ID: r["name"], Name: r["name"], Target: r["what"], Hash: r["hash"], Created: r["created"], Definer: r["definer"]}
		}},
}

// magentoQueries list Magento's ways back in: integrations and the admin tokens of the REST API
// (customers' tokens are left out), layout updates and email templates, which Magento renders
// through its template engine, and customers whose names carry template code. The newest rows
// come first, so what is added is always within the bound.
func magentoQueries(t string) []objectQuery {
	return []objectQuery{
		{ObjectIntegration, limit(`SELECT integration_id AS id, name, status AS what, created_at AS created,
			SHA2(CONCAT_WS('|', name, email, endpoint, identity_link_url, status, setup_type), 256) AS hash
			FROM ` + t + `integration ORDER BY integration_id DESC`),
			func(r map[string]string) DBObject {
				return DBObject{ID: r["id"], Name: r["name"], Target: "status " + r["what"], Hash: r["hash"], Created: r["created"]}
			}},
		{ObjectAdminToken, limit(`SELECT entity_id AS id, COALESCE(admin_id, '') AS admin, COALESCE(consumer_id, '') AS consumer, type AS what, created_at AS created
			FROM ` + t + `oauth_token WHERE customer_id IS NULL AND revoked = 0 ORDER BY entity_id DESC`),
			func(r map[string]string) DBObject {
				target := "integration " + r["consumer"]
				if r["admin"] != "" {
					target = "administrator " + r["admin"]
				}
				return DBObject{ID: r["id"], Name: r["what"], Target: target, Created: r["created"]}
			}},
		{ObjectLayoutUpdate, limit(`SELECT layout_update_id AS id, handle, SHA2(xml, 256) AS hash, LEFT(xml, 65535) AS body
			FROM ` + t + `layout_update ORDER BY layout_update_id DESC`),
			func(r map[string]string) DBObject {
				return DBObject{ID: r["id"], Name: r["handle"], Hash: r["hash"], Markers: markers(r["body"], codeMarkers)}
			}},
		{ObjectEmailTemplate, limit(`SELECT template_id AS id, template_code AS name, modified_at AS created,
			SHA2(CONCAT_WS('|', template_subject, template_text), 256) AS hash, LEFT(CONCAT_WS('|', template_subject, template_text), 65535) AS body
			FROM ` + t + `email_template ORDER BY template_id DESC`),
			func(r map[string]string) DBObject {
				return DBObject{ID: r["id"], Name: r["name"], Hash: r["hash"], Created: r["created"], Markers: markers(r["body"], codeMarkers)}
			}},
		{ObjectCustomer, limit(`SELECT entity_id AS id, created_at AS created, CONCAT_WS(' ', prefix, firstname, middlename, lastname, suffix) AS body
			FROM ` + t + `customer_entity WHERE ` + anyLike([]string{"prefix", "firstname", "middlename", "lastname", "suffix"}, templateMarkers) + ` ORDER BY entity_id DESC`),
			func(r map[string]string) DBObject {
				return DBObject{ID: r["id"], Created: r["created"], Markers: markers(r["body"], templateMarkers)}
			}},
	}
}

// anyLike builds a condition matching any of the markers in any of the columns. The markers
// are constants; "_" and "%" in them would be wildcards, and none holds one.
func anyLike(cols, list []string) string {
	var parts []string
	for _, c := range cols {
		for _, m := range list {
			parts = append(parts, "LOWER("+c+") LIKE '%"+strings.ReplaceAll(m, "'", "''")+"%'")
		}
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// readObjects runs the queries and records which kinds were read: a kind whose query failed
// (an older Magento without the table, a missing privilege) is not compared, so its objects do
// not all look new once it can be read.
func readObjects(ctx context.Context, db querier, queries []objectQuery, p *Profile) {
	for _, q := range queries {
		rows, ok := runChecked(ctx, db, p, q.sql)
		if !ok {
			continue
		}
		truncated(p, rows, q.kind+" objects")
		for _, r := range rows {
			o := q.object(r)
			if o.Kind == "" {
				o.Kind = q.kind
			}
			p.Objects = append(p.Objects, o)
		}
		for _, k := range kindsOf(q.kind) {
			if !slices.Contains(p.ObjectsRead, k) {
				p.ObjectsRead = append(p.ObjectsRead, k)
			}
		}
	}
}

func kindsOf(queryKind string) []string {
	if queryKind == "routine" {
		return []string{ObjectProcedure, ObjectFunction}
	}
	return []string{queryKind}
}
