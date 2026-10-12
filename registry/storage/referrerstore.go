package storage

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// referrersTagMaxLength is the maximum length of a tag following the
// referrers tag schema.
const referrersTagMaxLength = 128

var _ distribution.ReferrerService = &referrerStore{}

// referrerStore provides access to the index of manifests referring to other
// manifests through their subject field. The index is made up of links,
// keyed by the digest of the subject, which are written when a manifest with
// a subject is put into the repository.
type referrerStore struct {
	repository *repository
	blobStore  *blobStore
}

// Referrers returns the referrer service of the repository.
func (repo *repository) Referrers(ctx context.Context) (distribution.ReferrerService, error) {
	return &referrerStore{
		repository: repo,
		blobStore:  repo.blobStore,
	}, nil
}

// Referrers returns the descriptors of all manifests in the repository which
// have the provided digest as their subject.
func (rs *referrerStore) Referrers(ctx context.Context, subject digest.Digest) ([]v1.Descriptor, error) {
	if err := subject.Validate(); err != nil {
		return nil, err
	}

	manifests, err := rs.repository.Manifests(ctx)
	if err != nil {
		return nil, err
	}

	candidates, err := rs.linked(ctx, subject)
	if err != nil {
		return nil, err
	}

	// Manifests pushed by clients using the referrers tag schema may not be
	// part of the index, include them as well.
	tagged, err := rs.tagged(ctx, manifests, subject)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, tagged...)

	seen := make(map[digest.Digest]struct{}, len(candidates))
	referrers := make([]v1.Descriptor, 0, len(candidates))
	for _, dgst := range candidates {
		if _, ok := seen[dgst]; ok {
			continue
		}
		seen[dgst] = struct{}{}

		manifest, err := manifests.Get(ctx, dgst)
		if err != nil {
			var unknownRevision distribution.ErrManifestUnknownRevision
			if errors.As(err, &unknownRevision) {
				continue
			}
			return nil, err
		}

		if s := ocischema.SubjectOf(manifest); s == nil || s.Digest != subject {
			continue
		}

		desc, err := ocischema.ReferrerDescriptor(manifest)
		if err != nil {
			return nil, err
		}
		desc.Digest = dgst

		referrers = append(referrers, desc)
	}

	sort.Slice(referrers, func(i, j int) bool {
		return referrers[i].Digest < referrers[j].Digest
	})

	return referrers, nil
}

// link adds the referrer to the index of the subject.
func (rs *referrerStore) link(ctx context.Context, subject, referrer digest.Digest) error {
	linkPath, err := pathFor(manifestReferrerEntryLinkPathSpec{
		name:     rs.repository.Named().Name(),
		subject:  subject,
		referrer: referrer,
	})
	if err != nil {
		return err
	}

	return rs.blobStore.link(ctx, linkPath, referrer)
}

// linked returns the digests of the manifests in the index of the subject
// which are still present in the repository.
func (rs *referrerStore) linked(ctx context.Context, subject digest.Digest) ([]digest.Digest, error) {
	name := rs.repository.Named().Name()
	lbs := &linkedBlobStore{
		blobStore: rs.blobStore,
		blobAccessController: &linkedBlobStatter{
			blobStore:  rs.blobStore,
			repository: rs.repository,
			linkPath:   manifestRevisionLinkPath,
		},
		repository: rs.repository,
		ctx:        ctx,
		linkPath: func(name string, dgst digest.Digest) (string, error) {
			return pathFor(manifestReferrerEntryLinkPathSpec{
				name:     name,
				subject:  subject,
				referrer: dgst,
			})
		},
		linkDirectoryPathSpec: manifestReferrersSubjectPathSpec{
			name:    name,
			subject: subject,
		},
	}

	var dgsts []digest.Digest
	err := lbs.Enumerate(ctx, func(dgst digest.Digest) error {
		dgsts = append(dgsts, dgst)
		return nil
	})
	if err != nil {
		if errors.As(err, new(storagedriver.PathNotFoundError)) {
			return nil, nil
		}
		return nil, err
	}

	return dgsts, nil
}

// tagged returns the digests of the manifests listed in the image index
// tagged following the referrers tag schema for the subject, if there is one.
func (rs *referrerStore) tagged(ctx context.Context, manifests distribution.ManifestService, subject digest.Digest) ([]digest.Digest, error) {
	desc, err := rs.repository.Tags(ctx).Get(ctx, referrersTag(subject))
	if err != nil {
		var unknownTag distribution.ErrTagUnknown
		if errors.As(err, &unknownTag) {
			return nil, nil
		}
		return nil, err
	}

	manifest, err := manifests.Get(ctx, desc.Digest)
	if err != nil {
		var unknownRevision distribution.ErrManifestUnknownRevision
		if errors.As(err, &unknownRevision) {
			return nil, nil
		}
		return nil, err
	}

	index, ok := manifest.(*ocischema.DeserializedImageIndex)
	if !ok {
		return nil, nil
	}

	dgsts := make([]digest.Digest, 0, len(index.Manifests))
	for _, m := range index.Manifests {
		if m.Digest.Validate() != nil {
			continue
		}
		dgsts = append(dgsts, m.Digest)
	}

	return dgsts, nil
}

// referrersTag returns the tag used by the referrers tag schema for the
// provided subject.
func referrersTag(subject digest.Digest) string {
	tag := subject.Algorithm().String() + "-" + subject.Encoded()
	if len(tag) > referrersTagMaxLength {
		tag = tag[:referrersTagMaxLength]
	}
	return tag
}

// enumerateReferrerLinks calls fn with the subject and the referrer of each
// entry in the referrers index of the named repository, whether the referrer
// is still present in the repository or not.
func enumerateReferrerLinks(ctx context.Context, driver storagedriver.StorageDriver, repoName string, fn func(subject, referrer digest.Digest) error) error {
	root, err := pathFor(manifestReferrersPathSpec{name: repoName})
	if err != nil {
		return err
	}

	err = driver.Walk(ctx, root, func(fileInfo storagedriver.FileInfo) error {
		if fileInfo.IsDir() {
			return nil
		}

		// <subject algorithm>/<subject hex>/<referrer algorithm>/<referrer hex>/link
		components := strings.Split(strings.TrimPrefix(fileInfo.Path(), root+"/"), "/")
		if len(components) != 5 || components[4] != "link" {
			return nil
		}

		subject := digest.NewDigestFromEncoded(digest.Algorithm(components[0]), components[1])
		referrer := digest.NewDigestFromEncoded(digest.Algorithm(components[2]), components[3])
		if subject.Validate() != nil || referrer.Validate() != nil {
			return nil
		}

		return fn(subject, referrer)
	})
	if err != nil && !errors.As(err, new(storagedriver.PathNotFoundError)) {
		return err
	}

	return nil
}
