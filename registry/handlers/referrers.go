package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/gorilla/handlers"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// referrersDispatcher constructs the referrers handler api endpoint.
func referrersDispatcher(ctx *Context, r *http.Request) http.Handler {
	// When referrers cannot be listed, the endpoint has to respond as if it
	// does not exist, which makes clients fall back to the referrers tag
	// schema.
	service, err := referrerService(ctx)
	if err != nil {
		return http.NotFoundHandler()
	}

	dgst, err := getDigest(ctx)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx.Errors = append(ctx.Errors, errcode.ErrorCodeDigestInvalid.WithDetail(err))
		})
	}

	referrersHandler := &referrersHandler{
		Context:   ctx,
		Digest:    dgst,
		referrers: service,
	}

	return handlers.MethodHandler{
		http.MethodGet: http.HandlerFunc(referrersHandler.GetReferrers),
	}
}

// referrersHandler handles requests for lists of referrers of a manifest
// under a repository name.
type referrersHandler struct {
	*Context

	// Digest is the digest of the subject.
	Digest digest.Digest

	referrers distribution.ReferrerService
}

// GetReferrers returns an image index of the manifests which have the
// requested digest as their subject.
func (rh *referrersHandler) GetReferrers(w http.ResponseWriter, r *http.Request) {
	descriptors, err := rh.referrers.Referrers(rh, rh.Digest)
	if err != nil {
		rh.Errors = append(rh.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
		return
	}

	if artifactType := r.URL.Query().Get("artifactType"); artifactType != "" {
		filtered := make([]v1.Descriptor, 0, len(descriptors))
		for _, desc := range descriptors {
			if desc.ArtifactType == artifactType {
				filtered = append(filtered, desc)
			}
		}
		descriptors = filtered
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}

	// The list of manifests has to be present in the response, even if empty.
	if descriptors == nil {
		descriptors = []v1.Descriptor{}
	}

	p, err := json.Marshal(v1.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageIndex,
		Manifests: descriptors,
	})
	if err != nil {
		rh.Errors = append(rh.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
		return
	}

	w.Header().Set("Content-Type", v1.MediaTypeImageIndex)
	w.Header().Set("Content-Length", strconv.Itoa(len(p)))
	if _, err := w.Write(p); err != nil {
		rh.Errors = append(rh.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
		return
	}
}

// referrerService returns the referrer service of the repository in the
// context. distribution.ErrUnsupported is returned if referrers cannot be
// listed, which is the case for a pull through cache.
func referrerService(ctx *Context) (distribution.ReferrerService, error) {
	if ctx.App.isCache {
		return nil, distribution.ErrUnsupported
	}

	provider, ok := ctx.Repository.(distribution.ReferrerProvider)
	if !ok {
		return nil, distribution.ErrUnsupported
	}

	return provider.Referrers(ctx)
}
