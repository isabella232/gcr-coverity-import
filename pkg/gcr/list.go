package gcr

import (
	"context"
	"fmt"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1beta1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"go.uber.org/zap"
	grafeas "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

func FindImage(root, project, service, tag string) (string, error) {
	repoName := fmt.Sprintf("%s/%s/%s", root, project, service)
	repo, err := name.NewRepository(repoName)
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
				if t == tag {
					out = fmt.Sprintf("%s@%s", repo, digest)
					return nil
				}
			}
		}
		return fmt.Errorf("did not find tag %q for service %q", tag, service)
	}
	if err := google.Walk(repo, filterTags, google.WithAuth(auth)); err != nil {
		return "", err
	}
	return out, nil
}

func ListVulns(project, image string) (*containeranalysis.OccurrenceIterator, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewGrafeasV1Beta1Client(ctx)
	if err != nil {
		return nil, err
	}

	resourceURL := "https://" + image

	req := &grafeas.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", project),
		Filter: fmt.Sprintf("resourceUrl = %q kind = %q", resourceURL, "VULNERABILITY"),
	}

	zap.L().Info("request", zap.Stringer("ListOccurrencesRequest", req))

	res := client.ListOccurrences(ctx, req)
	return res, nil
}
