package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func emit(format string, a ...any) {
	fmt.Printf(format+"\n", a...)
}

// GCOpts contains options for garbage collector
type GCOpts struct {
	DryRun         bool
	RemoveUntagged bool
	Quiet          bool
}

// ManifestDel contains manifest structure which will be deleted
type ManifestDel struct {
	Name   string
	Digest digest.Digest
	Tags   []string
}

// MarkAndSweep performs a mark and sweep of registry data
func MarkAndSweep(ctx context.Context, storageDriver driver.StorageDriver, registry distribution.Namespace, opts GCOpts) error {
	repositoryEnumerator, ok := registry.(distribution.RepositoryEnumerator)
	if !ok {
		return fmt.Errorf("unable to convert Namespace to RepositoryEnumerator")
	}

	// mark
	markSet := make(map[digest.Digest]struct{})
	deleteLayerSet := make(map[string][]digest.Digest)
	manifestArr := make([]ManifestDel, 0)
	var repoNames []string
	err := repositoryEnumerator.Enumerate(ctx, func(repoName string) error {
		if !opts.Quiet {
			emit(repoName)
		}

		var err error
		named, err := reference.WithName(repoName)
		if err != nil {
			return fmt.Errorf("failed to parse repo name %s: %v", repoName, err)
		}
		repository, err := registry.Repository(ctx, named)
		if err != nil {
			return fmt.Errorf("failed to construct repository: %v", err)
		}

		manifestService, err := repository.Manifests(ctx)
		if err != nil {
			return fmt.Errorf("failed to construct manifest service: %v", err)
		}

		manifestEnumerator, ok := manifestService.(distribution.ManifestEnumerator)
		if !ok {
			return fmt.Errorf("unable to convert ManifestService into ManifestEnumerator")
		}

		repoNames = append(repoNames, repoName)
		markBlob := func(d digest.Digest) bool {
			_, marked := markSet[d]
			if !marked {
				markSet[d] = struct{}{}
				if !opts.Quiet {
					emit("%s: marking blob %s", repoName, d)
				}
			}
			return marked
		}

		// untagged manifests of this repository start at this offset
		untaggedOffset := len(manifestArr)

		err = manifestEnumerator.Enumerate(ctx, func(dgst digest.Digest) error {
			if opts.RemoveUntagged {
				// fetch all tags where this manifest is the latest one
				tags, err := repository.Tags(ctx).Lookup(ctx, v1.Descriptor{Digest: dgst})
				if err != nil {
					return fmt.Errorf("failed to retrieve tags for digest %v: %v", dgst, err)
				}
				if len(tags) == 0 {
					// fetch all tags from repository
					// all of these tags could contain manifest in history
					// which means that we need check (and delete) those references when deleting manifest
					allTags, err := repository.Tags(ctx).All(ctx)
					if err != nil {
						if _, ok := err.(distribution.ErrRepositoryUnknown); ok {
							if !opts.Quiet {
								emit("manifest tags path of repository %s does not exist", repoName)
							}
							return nil
						}
						return fmt.Errorf("failed to retrieve tags %v", err)
					}
					manifestArr = append(manifestArr, ManifestDel{Name: repoName, Digest: dgst, Tags: allTags})
					return nil
				}
			}
			// Mark the manifest's blob
			if !opts.Quiet {
				emit("%s: marking manifest %s ", repoName, dgst)
			}
			markSet[dgst] = struct{}{}

			return markManifestReferences(dgst, manifestService, ctx, markBlob)
		})

		if err != nil {
			// In certain situations such as unfinished uploads, deleting all
			// tags in S3 or removing the _manifests folder manually, this
			// error may be of type PathNotFound.
			//
			// In these cases we can continue marking other manifests safely.
			if _, ok := err.(driver.PathNotFoundError); !ok {
				return err
			}
		}

		// Untagged manifests referring to a manifest which is kept are kept
		// as well, otherwise the referrers of an image would not survive.
		err = markReferrers(ctx, manifestService, manifestArr[untaggedOffset:], markSet, func(dgst digest.Digest) error {
			if !opts.Quiet {
				emit("%s: marking referrer manifest %s ", repoName, dgst)
			}
			markSet[dgst] = struct{}{}

			return markManifestReferences(dgst, manifestService, ctx, markBlob)
		})
		if err != nil {
			return err
		}
		blobService := repository.Blobs(ctx)
		layerEnumerator, ok := blobService.(distribution.ManifestEnumerator)
		if !ok {
			return errors.New("unable to convert BlobService into ManifestEnumerator")
		}

		var deleteLayers []digest.Digest
		err = layerEnumerator.Enumerate(ctx, func(dgst digest.Digest) error {
			if _, ok := markSet[dgst]; !ok {
				deleteLayers = append(deleteLayers, dgst)
			}
			return nil
		})
		if len(deleteLayers) > 0 {
			deleteLayerSet[repoName] = deleteLayers
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to mark: %v", err)
	}

	manifestArr = unmarkReferencedManifest(manifestArr, markSet, opts.Quiet)

	// sweep
	vacuum := NewVacuum(ctx, storageDriver)
	if !opts.DryRun {
		for _, obj := range manifestArr {
			err = vacuum.RemoveManifest(obj.Name, obj.Digest, obj.Tags)
			if err != nil {
				return fmt.Errorf("failed to delete manifest %s: %v", obj.Digest, err)
			}
		}
	}

	// The referrers index may hold entries of manifests which have been
	// deleted, either above or through the API.
	for _, repoName := range repoNames {
		err = sweepReferrerLinks(ctx, storageDriver, vacuum, repoName, opts)
		if err != nil {
			return fmt.Errorf("failed to sweep referrers of repo %s: %v", repoName, err)
		}
	}

	blobService := registry.Blobs()
	deleteSet := make(map[digest.Digest]struct{})
	err = blobService.Enumerate(ctx, func(dgst digest.Digest) error {
		// check if digest is in markSet. If not, delete it!
		if _, ok := markSet[dgst]; !ok {
			deleteSet[dgst] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error enumerating blobs: %v", err)
	}
	if !opts.Quiet {
		emit("\n%d blobs marked, %d blobs and %d manifests eligible for deletion", len(markSet), len(deleteSet), len(manifestArr))
	}
	for dgst := range deleteSet {
		if !opts.Quiet {
			emit("blob eligible for deletion: %s", dgst)
		}
		if opts.DryRun {
			continue
		}
		err = vacuum.RemoveBlob(string(dgst))
		if err != nil {
			return fmt.Errorf("failed to delete blob %s: %v", dgst, err)
		}
	}

	for repo, dgsts := range deleteLayerSet {
		for _, dgst := range dgsts {
			if !opts.Quiet {
				emit("%s: layer link eligible for deletion: %s", repo, dgst)
			}
			if opts.DryRun {
				continue
			}
			err = vacuum.RemoveLayer(repo, dgst)
			if err != nil {
				return fmt.Errorf("failed to delete layer link %s of repo %s: %v", dgst, repo, err)
			}
		}
	}

	return err
}

// unmarkReferencedManifest filters out manifest present in markSet
func unmarkReferencedManifest(manifestArr []ManifestDel, markSet map[digest.Digest]struct{}, quietOutput bool) []ManifestDel {
	filtered := make([]ManifestDel, 0)
	for _, obj := range manifestArr {
		if _, ok := markSet[obj.Digest]; !ok {
			if !quietOutput {
				emit("manifest eligible for deletion: %s", obj)
			}

			filtered = append(filtered, obj)
		}
	}
	return filtered
}

// markManifestReferences marks the manifest references
func markManifestReferences(dgst digest.Digest, manifestService distribution.ManifestService, ctx context.Context, ingester func(digest.Digest) bool) error {
	manifest, err := manifestService.Get(ctx, dgst)
	if err != nil {
		return fmt.Errorf("failed to retrieve manifest for digest %v: %v", dgst, err)
	}

	descriptors := manifest.References()
	for _, descriptor := range descriptors {

		// do not visit references if already marked
		if ingester(descriptor.Digest) {
			continue
		}

		if ok, _ := manifestService.Exists(ctx, descriptor.Digest); ok {
			err := markManifestReferences(descriptor.Digest, manifestService, ctx, ingester)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// markReferrers calls mark for each of the untagged manifests which has to be
// kept because the manifest it refers to with its subject is kept. As mark is
// expected to add the manifest to the markSet, the referrers of a referrer
// are kept as well.
func markReferrers(ctx context.Context, manifestService distribution.ManifestService, untagged []ManifestDel, markSet map[digest.Digest]struct{}, mark func(digest.Digest) error) error {
	// subjects of the untagged manifests which have one
	subjects := make(map[digest.Digest]digest.Digest)
	candidates := make(map[digest.Digest]struct{}, len(untagged))
	for _, obj := range untagged {
		candidates[obj.Digest] = struct{}{}

		manifest, err := manifestService.Get(ctx, obj.Digest)
		if err != nil {
			// manifests which cannot be read do not keep anything alive
			continue
		}
		if subject := ocischema.SubjectOf(manifest); subject != nil {
			subjects[obj.Digest] = subject.Digest
		}
	}

	// a subject is kept if it is present in the repository and is either
	// tagged or marked
	kept := func(subject digest.Digest) bool {
		if _, marked := markSet[subject]; !marked {
			if _, untagged := candidates[subject]; untagged {
				return false
			}
		}
		exists, _ := manifestService.Exists(ctx, subject)
		return exists
	}

	for progress := true; progress; {
		progress = false
		for _, obj := range untagged {
			subject, ok := subjects[obj.Digest]
			if !ok {
				continue
			}
			if _, marked := markSet[obj.Digest]; marked {
				delete(subjects, obj.Digest)
				continue
			}
			if !kept(subject) {
				continue
			}
			if err := mark(obj.Digest); err != nil {
				return err
			}
			delete(subjects, obj.Digest)
			progress = true
		}
	}

	return nil
}

// sweepReferrerLinks removes the entries of the referrers index of the named
// repository which point to manifests no longer present in the repository.
func sweepReferrerLinks(ctx context.Context, storageDriver driver.StorageDriver, vacuum Vacuum, repoName string, opts GCOpts) error {
	type referrerLink struct {
		subject, referrer digest.Digest
	}

	var stale []referrerLink
	err := enumerateReferrerLinks(ctx, storageDriver, repoName, func(subject, referrer digest.Digest) error {
		revisionLinkPath, err := manifestRevisionLinkPath(repoName, referrer)
		if err != nil {
			return err
		}
		if _, err := storageDriver.Stat(ctx, revisionLinkPath); err != nil {
			if _, ok := err.(driver.PathNotFoundError); !ok {
				return err
			}
			stale = append(stale, referrerLink{subject: subject, referrer: referrer})
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, link := range stale {
		if !opts.Quiet {
			emit("%s: referrer link eligible for deletion: %s -> %s", repoName, link.referrer, link.subject)
		}
		if opts.DryRun {
			continue
		}
		if err := vacuum.RemoveReferrerLink(repoName, link.subject, link.referrer); err != nil {
			return err
		}
	}

	return nil
}
