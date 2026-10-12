package distribution

import (
	"context"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// ReferrerService lists the manifests in a repository which refer to another
// manifest through their subject field.
type ReferrerService interface {
	// Referrers returns the descriptors of all manifests in the repository
	// whose subject is the provided digest. The subject is not required to
	// exist. If there are no referrers, an empty list is returned.
	Referrers(ctx context.Context, subject digest.Digest) ([]v1.Descriptor, error)
}

// ReferrerProvider is optionally implemented by a Repository which supports
// listing referrers.
type ReferrerProvider interface {
	// Referrers returns a reference to this repository's referrer service.
	// ErrUnsupported is returned if the repository cannot list referrers.
	Referrers(ctx context.Context) (ReferrerService, error)
}
