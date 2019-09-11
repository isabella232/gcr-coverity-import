package main

import (
	"context"
	"flag"
	"fmt"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1beta1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"google.golang.org/api/iterator"
	grafeas "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

var (
	project = flag.String("project", "dev-vml-cm", "Google Project ID")
	root    = flag.String("root", "eu.gcr.io", "GCR Root")
	service = flag.String("service", "", `Service to report on, ie. "ssn-pdfservice"`)
	tag     = flag.String("tag", "master", "Docker tag to report on")
)

func findImage() (string, error) {
	root := fmt.Sprintf("%s/%s/%s", *root, *project, *service)
	repo, err := name.NewRepository(root)
	if err != nil {
		return "", err
	}

	auth, err := google.Keychain.Resolve(repo.Registry)
	if err != nil {
		return "", err
	}

	var out string

	filterTags := func(repo name.Repository, tags *google.Tags, err error) error {
		if err != nil {
			return err
		}
		for digest, manifest := range tags.Manifests {
			for _, t := range manifest.Tags {
				if t == *tag {
					out = fmt.Sprintf("%s@%s", repo, digest)
					return nil
				}
			}
		}
		return fmt.Errorf("did not find tag %q for service %q", *tag, *service)
	}
	if err := google.Walk(repo, filterTags, google.WithAuth(auth)); err != nil {
		return "", err
	}
	return out, nil
}

func listVulns(image string) error {
	ctx := context.Background()
	client, err := containeranalysis.NewGrafeasV1Beta1Client(ctx)
	if err != nil {
		return err
	}

	resourceURL := "https://" + image

	req := &grafeas.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", *project),
		Filter: fmt.Sprintf("resourceUrl = %q kind = %q", resourceURL, "VULNERABILITY"),
	}

	println(req.String())

	res := client.ListOccurrences(ctx, req)

	var occur *grafeas.Occurrence
	for {
		occur, err = res.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			return err
		}
		println(occur.String())
	}

	return nil
}

func do() error {
	if *service == "" {
		return fmt.Errorf("service must be set")
	}
	imagehash, err := findImage()
	if err != nil {
		return err
	}
	fmt.Println(imagehash)
	err = listVulns(imagehash)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	if err := do(); err != nil {
		panic(err)
	}
}
