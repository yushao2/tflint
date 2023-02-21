package formatter

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/hcl/v2"
	sdk "github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint/tflint"
)

// JSONIssue is a temporary structure for converting TFLint issues to JSON.
type JSONIssue struct {
	Description string       `json:"description"`
	Fingerprint string       `json:"fingerprint"`
	Severity    string       `json:"severity"`
	Location    JSONLocation `json:"location"`
}

// JSONLocation is a temporary structure for converting TFLint rules to JSON.
type JSONLocation struct {
	Path  string    `json:"path"`
	Lines JSONLines `json:"lines"`
}

// JSONLines is a temporary structure for converting TFLint rules to JSON.
type JSONLines struct {
	Begin int `json:"begin"`
}



func (f *Formatter) gitlabPrint(issues tflint.Issues, appErr error) {
	ret := make([]JSONIssue, len(issues))
	errs := make([]JSONIssue, 0)
	for idx, issue := range issues.Sort() {
		ret[idx] = JSONIssue{
			Description: fmt.Sprintf("%s (%s)", issue.Message, issue.Rule.Name()),
			Fingerprint: GetMD5Hash(fmt.Sprintf("%s%s%d", issue.Rule.Name(), issue.Range.Filename, issue.Range.Start.Line)),
			Severity: toGitLabSeverity(issue.Rule.Severity()),
			Location: JSONLocation{
				Path: issue.Range.Filename,
				Lines: JSONLines{
					Begin: issue.Range.Start.Line
				}
			}
		}
	}

	if appErr != nil {
		var diags hcl.Diagnostics
		if errors.As(appErr, &diags) {
			errs = make([]JSONIssue, len(diags))
			for idx, diag := range diags {
				errs[idx] = JSONIssue{
					Description: diag.Detail
					Fingerprint: GetMD5Hash(fmt.Sprintf("%s%s%d", diag.summary, diag.Subject.Filename, diag.Subject.Start.Line)),
					Severity: gitLabFromHclSeverity(diag.Severity),
					Location: JSONLocation {
						Path: diag.Subject.Filename,
						Lines: JSONLines{
							Begin: diag.Subject.Start.Line
						}
					}
				}
			}
		} else {
			errs = []JSONIssue{{
				Severity: toGitLabSeverity(sdk.ERROR),
				Description:  appErr.Error()
			}}
		}
	}

	out, err := json.Marshal(append(ret, errs...))
	if err != nil {
		fmt.Fprint(f.Stderr, err)
	}
	fmt.Fprint(f.Stdout, string(out))
}

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func toGitLabSeverity(lintType tflint.Severity) string {
	switch lintType {
	case sdk.ERROR:
		return "major"
	case sdk.WARNING:
		return "minor"
	case sdk.NOTICE:
		return "info"
	default:
		panic(fmt.Errorf("Unexpected lint type: %s", lintType))
	}
}

func gitLabFromHclSeverity(severity hcl.DiagnosticSeverity) string {
	switch severity {
	case hcl.DiagError:
		return "error"
	case hcl.DiagWarning:
		return "warning"
	default:
		panic(fmt.Errorf("Unexpected HCL severity: %v", severity))
	}
}
