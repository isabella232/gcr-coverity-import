package coverity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1beta1"
	"github.com/golang/protobuf/jsonpb"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"
	grafeas "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

type Header struct {
	Version int    `json:"version"`
	Format  string `json:"format"`
}

type Source struct {
	File     string `json:"file"`
	Encoding string `json:"encoding"`
}

type Issue struct {
	Checker     string   `json:"checker"`
	Extra       string   `json:"extra"`
	File        string   `json:"file"`
	Function    string   `json:"function"`
	Subcategory string   `json:"subcategory"`
	Properties  Property `json:"properties"`
	Events      []Event  `json:"events"`
}

type Property struct {
	Type            string `json:"type"`
	Category        string `json:"category"`
	Impact          string `json:"impact"`
	CWE             int    `json:"cwe"`
	LongDescription string `json:"longDescription"`
	LocalEffect     string `json:"localEffect"`
	IssueKind       string `json:"issueKind"`
}

type Event struct {
	Tag         string `json:"tag"`
	Description string `json:"description"`
	File        string `json:"file"`
	LinkURL     string `json:"linkUrl"`
	LinkText    string `json:"linkText"`
	Line        int    `json:"line"`
	Main        bool   `json:"main"`
}

type Results struct {
	Header  Header   `json:"header"`
	Sources []Source `json:"sources"`
	Issues  []Issue  `json:"issues"`
}

func TransformGrafeas(occs *containeranalysis.OccurrenceIterator, basedir string) (*Results, error) {
	results := &Results{
		Header: Header{
			Version: 1,
			Format:  "cov-import-results input",
		},
		Sources: make([]Source, 0),
		Issues:  make([]Issue, 0),
	}

	var occur *grafeas.Occurrence
	var err error
	for {
		occur, err = occs.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		iss, err := TransformOccurance(occur, basedir)
		if err != nil {
			return nil, err
		}
		results.Issues = append(results.Issues, *iss)
		results.Sources = append(results.Sources, Source{
			File:     iss.File,
			Encoding: "UTF-8",
		})
	}
	return results, nil
}

func filenameSanitize(r rune) rune {
	// https://docs.microsoft.com/en-us/windows/win32/msi/filename
	switch r {
	case '/':
		return '_'
	case '+', ',', ';', '=', '[', ']', '\\', '?', '|', '<', '>', ':', '*', '"':
		return '.'
	default:
		return r
	}
}

func TransformOccurance(occ *grafeas.Occurrence, basedir string) (*Issue, error) {
	vuln := occ.GetVulnerability()
	if vuln == nil {
		return nil, fmt.Errorf("only vulnerabilities can be converted")
	}

	packs := vuln.GetPackageIssue()
	if len(packs) == 0 {
		return nil, fmt.Errorf("only vulnerable packages can be converted")
	}
	pack := packs[0]

	filename := fmt.Sprintf("%s/%s:%s_.json",
		pack.GetAffectedLocation().GetCpeUri(),
		pack.GetAffectedLocation().GetPackage(),
		pack.GetAffectedLocation().GetVersion().GetName(),
	)
	// Sanitize filename
	filename = strings.Map(filenameSanitize, filename)
	path := filepath.Join(basedir, filename)
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	eventPath := filepath.Join(basedir, filepath.Base(occ.GetName())+".json")
	absEventPath, err := filepath.Abs(eventPath)
	if err != nil {
		return nil, err
	}

	zap.L().Info("writing file",
		zap.String("module", path),
		zap.String("event", eventPath),
	)
	mar := &jsonpb.Marshaler{
		EmitDefaults: false,
		Indent:       "  ",
	}
	moduleFile, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	eventFile, err := os.Create(eventPath)
	if err != nil {
		return nil, err
	}
	f := io.MultiWriter(moduleFile, eventFile)
	err = mar.Marshal(f, occ)
	if err != nil {
		return nil, err
	}

	events := make([]Event, 0, len(vuln.GetRelatedUrls()))
	for _, re := range vuln.GetRelatedUrls() {
		events = append(events, Event{
			Tag:         "vulnerable_component",
			Description: fmt.Sprintf("%s has known vulnerabilities", strings.Title(pack.GetAffectedLocation().GetPackage())),
			File:        strings.ReplaceAll(absEventPath, "\\", "/"),
			LinkURL:     re.GetUrl(),
			LinkText:    re.GetLabel(),
			Line:        1,
			Main:        true,
		})
	}

	iss := &Issue{
		Checker:     "VULNERABLE_CONTAINER_COMPONENT",
		Extra:       pack.GetAffectedLocation().GetPackage(),
		File:        strings.ReplaceAll(absPath, "\\", "/"),
		Subcategory: occ.GetKind().String(),
		Properties: Property{
			Type:            "Use of vulnerable container component",
			Category:        fmt.Sprintf("%s impact component in container", strings.Title(strings.ToLower(pack.GetSeverityName()))),
			Impact:          CoverityImpact(pack.GetSeverityName()),
			LongDescription: fmt.Sprintf("%s: %s", vuln.GetShortDescription(), vuln.GetLongDescription()),
			IssueKind:       "SECURITY",
			CWE:             937,
			LocalEffect:     fmt.Sprintf("%s has known vulnerabilities", pack.GetAffectedLocation().GetPackage()),
		},
		Events: events,
	}
	return iss, nil
}

func CoverityImpact(name string) string {
	switch {
	case strings.EqualFold(name, "low"):
		return "Low"
	case strings.EqualFold(name, "High"):
		return "High"
	default:
		return "Medium"
	}
}
