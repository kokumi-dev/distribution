package storage

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const testReferrerArtifactType = "application/vnd.example.sbom.v1"

// makeReferrer creates an artifact manifest referring to the subject. The
// name ends up in the annotations, making the manifest unique.
func makeReferrer(t *testing.T, repository distribution.Repository, subject digest.Digest, artifactType, name string) *ocischema.DeserializedManifest {
	t.Helper()
	ctx := dcontext.Background()

	config, err := repository.Blobs(ctx).Put(ctx, v1.MediaTypeEmptyJSON, []byte("{}"))
	if err != nil {
		t.Fatalf("failed to upload config: %v", err)
	}
	config.MediaType = v1.MediaTypeEmptyJSON

	manifest, err := ocischema.FromStruct(ocischema.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    v1.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       config,
		Layers:       []v1.Descriptor{},
		Subject: &v1.Descriptor{
			MediaType: v1.MediaTypeImageManifest,
			Digest:    subject,
			Size:      1234,
		},
		Annotations: map[string]string{"org.example.name": name},
	})
	if err != nil {
		t.Fatalf("failed to create referrer: %v", err)
	}

	return manifest
}

// uploadReferrer creates a referrer of the subject and puts it into the
// repository.
func uploadReferrer(t *testing.T, repository distribution.Repository, subject digest.Digest, artifactType, name string) digest.Digest {
	t.Helper()

	dgst, err := makeManifestService(t, repository).Put(dcontext.Background(), makeReferrer(t, repository, subject, artifactType, name))
	if err != nil {
		t.Fatalf("failed to upload referrer: %v", err)
	}

	return dgst
}

func listReferrers(t *testing.T, repository distribution.Repository, subject digest.Digest) []v1.Descriptor {
	t.Helper()
	ctx := dcontext.Background()

	provider, ok := repository.(distribution.ReferrerProvider)
	if !ok {
		t.Fatal("repository does not provide referrers")
	}
	service, err := provider.Referrers(ctx)
	if err != nil {
		t.Fatalf("failed to construct referrer service: %v", err)
	}
	referrers, err := service.Referrers(ctx, subject)
	if err != nil {
		t.Fatalf("failed to list referrers: %v", err)
	}
	if referrers == nil {
		t.Fatal("list of referrers must not be nil")
	}

	return referrers
}

func referrerDigests(referrers []v1.Descriptor) map[digest.Digest]struct{} {
	dgsts := make(map[digest.Digest]struct{}, len(referrers))
	for _, desc := range referrers {
		dgsts[desc.Digest] = struct{}{}
	}
	return dgsts
}

func referrerLinks(t *testing.T, d driver.StorageDriver, repoName string) map[digest.Digest]digest.Digest {
	t.Helper()

	links := make(map[digest.Digest]digest.Digest)
	err := enumerateReferrerLinks(dcontext.Background(), d, repoName, func(subject, referrer digest.Digest) error {
		links[referrer] = subject
		return nil
	})
	if err != nil {
		t.Fatalf("failed to enumerate referrer links: %v", err)
	}

	return links
}

func TestReferrers(t *testing.T) {
	ctx := dcontext.Background()
	registry := createRegistry(t, inmemory.New())
	repo := makeRepository(t, registry, "referrers/list")

	// nothing has been pushed to the repository at all
	if referrers := listReferrers(t, repo, digest.FromString("unknown")); len(referrers) != 0 {
		t.Fatalf("unexpected referrers in empty repository: %v", referrers)
	}

	subject := uploadRandomOCIImage(t, repo)
	other := uploadRandomOCIImage(t, repo)
	if referrers := listReferrers(t, repo, subject.manifestDigest); len(referrers) != 0 {
		t.Fatalf("unexpected referrers: %v", referrers)
	}

	sbomManifest := makeReferrer(t, repo, subject.manifestDigest, testReferrerArtifactType, "sbom")
	sbom, err := makeManifestService(t, repo).Put(ctx, sbomManifest)
	if err != nil {
		t.Fatalf("failed to upload referrer: %v", err)
	}
	// without an artifactType, the media type of the config is used
	signature := uploadReferrer(t, repo, subject.manifestDigest, "", "signature")
	uploadReferrer(t, repo, other.manifestDigest, testReferrerArtifactType, "other")

	// pushing a referrer once more must not list it twice
	if _, err := makeManifestService(t, repo).Put(ctx, sbomManifest); err != nil {
		t.Fatalf("failed to upload referrer again: %v", err)
	}

	referrers := listReferrers(t, repo, subject.manifestDigest)
	if len(referrers) != 2 {
		t.Fatalf("expected 2 referrers, got %v", referrers)
	}
	for i := 1; i < len(referrers); i++ {
		if referrers[i-1].Digest >= referrers[i].Digest {
			t.Fatalf("referrers are not sorted by digest: %v", referrers)
		}
	}

	_, payload, err := sbomManifest.Payload()
	if err != nil {
		t.Fatalf("failed to get payload: %v", err)
	}
	expected := map[digest.Digest]v1.Descriptor{
		sbom: {
			MediaType:    v1.MediaTypeImageManifest,
			Digest:       sbom,
			Size:         int64(len(payload)),
			ArtifactType: testReferrerArtifactType,
			Annotations:  map[string]string{"org.example.name": "sbom"},
		},
	}
	for _, desc := range referrers {
		switch desc.Digest {
		case sbom:
			if !reflect.DeepEqual(desc, expected[sbom]) {
				t.Fatalf("unexpected descriptor: %#v, expected %#v", desc, expected[sbom])
			}
		case signature:
			if desc.ArtifactType != v1.MediaTypeEmptyJSON {
				t.Fatalf("expected artifactType to be the config media type, got %q", desc.ArtifactType)
			}
		default:
			t.Fatalf("unexpected referrer: %v", desc)
		}
	}

	// referrers of referrers are listed for the referrer only
	nested := uploadReferrer(t, repo, sbom, testReferrerArtifactType, "nested")
	if referrers := listReferrers(t, repo, sbom); len(referrers) != 1 || referrers[0].Digest != nested {
		t.Fatalf("unexpected referrers of referrer: %v", referrers)
	}
	if referrers := listReferrers(t, repo, subject.manifestDigest); len(referrers) != 2 {
		t.Fatalf("expected 2 referrers, got %v", referrers)
	}

	// referrers are scoped to the repository
	otherRepo := makeRepository(t, registry, "referrers/other")
	if referrers := listReferrers(t, otherRepo, subject.manifestDigest); len(referrers) != 0 {
		t.Fatalf("unexpected referrers in other repository: %v", referrers)
	}

	// deleted referrers are not listed anymore
	if err := makeManifestService(t, repo).Delete(ctx, sbom); err != nil {
		t.Fatalf("failed to delete referrer: %v", err)
	}
	if referrers := listReferrers(t, repo, subject.manifestDigest); len(referrers) != 1 || referrers[0].Digest != signature {
		t.Fatalf("unexpected referrers after delete: %v", referrers)
	}

	// deleting the subject keeps its referrers
	if err := makeManifestService(t, repo).Delete(ctx, subject.manifestDigest); err != nil {
		t.Fatalf("failed to delete subject: %v", err)
	}
	if referrers := listReferrers(t, repo, subject.manifestDigest); len(referrers) != 1 || referrers[0].Digest != signature {
		t.Fatalf("unexpected referrers after deleting the subject: %v", referrers)
	}
}

func TestReferrersMissingSubject(t *testing.T) {
	registry := createRegistry(t, inmemory.New())
	repo := makeRepository(t, registry, "referrers/missing")

	// the subject is pushed after its referrer
	subject, err := ocischema.FromStruct(ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    v1.DescriptorEmptyJSON,
		Layers:    []v1.Descriptor{},
	})
	if err != nil {
		t.Fatalf("failed to create subject: %v", err)
	}
	_, payload, err := subject.Payload()
	if err != nil {
		t.Fatalf("failed to get payload: %v", err)
	}
	subjectDigest := digest.FromBytes(payload)

	referrer := uploadReferrer(t, repo, subjectDigest, testReferrerArtifactType, "early")
	if referrers := listReferrers(t, repo, subjectDigest); len(referrers) != 1 || referrers[0].Digest != referrer {
		t.Fatalf("unexpected referrers of missing subject: %v", referrers)
	}

	if _, err := makeManifestService(t, repo).Put(dcontext.Background(), subject); err != nil {
		t.Fatalf("failed to upload subject: %v", err)
	}
	if referrers := listReferrers(t, repo, subjectDigest); len(referrers) != 1 || referrers[0].Digest != referrer {
		t.Fatalf("unexpected referrers: %v", referrers)
	}
}

func TestReferrersInvalidSubject(t *testing.T) {
	ctx := dcontext.Background()
	registry := createRegistry(t, inmemory.New())
	repo := makeRepository(t, registry, "referrers/invalid")

	manifest := makeReferrer(t, repo, "sha256:invalid", testReferrerArtifactType, "invalid")
	_, err := makeManifestService(t, repo).Put(ctx, manifest)
	if _, ok := err.(distribution.ErrManifestVerification); !ok {
		t.Fatalf("expected a verification error, got %v", err)
	}
	_, payload, err := manifest.Payload()
	if err != nil {
		t.Fatalf("failed to get payload: %v", err)
	}
	if exists, err := makeManifestService(t, repo).Exists(ctx, digest.FromBytes(payload)); err != nil || exists {
		t.Fatalf("manifest with invalid subject must not be stored: exists=%v, err=%v", exists, err)
	}

	provider := repo.(distribution.ReferrerProvider)
	service, err := provider.Referrers(ctx)
	if err != nil {
		t.Fatalf("failed to construct referrer service: %v", err)
	}
	if _, err := service.Referrers(ctx, "sha256:invalid"); err == nil {
		t.Fatal("expected an error listing referrers of an invalid digest")
	}
}

func TestReferrersIndex(t *testing.T) {
	ctx := dcontext.Background()
	registry := createRegistry(t, inmemory.New())
	repo := makeRepository(t, registry, "referrers/index")

	subject := uploadRandomOCIImage(t, repo)
	child := uploadRandomOCIImage(t, repo)

	index, err := ocischema.FromDescriptors([]v1.Descriptor{{
		MediaType: v1.MediaTypeImageManifest,
		Digest:    child.manifestDigest,
		Size:      1234,
	}}, map[string]string{"org.example.name": "index"})
	if err != nil {
		t.Fatalf("failed to create index: %v", err)
	}
	// FromDescriptors does not know about subjects, round trip the struct
	index.ArtifactType = "application/vnd.example.index.v1"
	index.Subject = &v1.Descriptor{MediaType: v1.MediaTypeImageManifest, Digest: subject.manifestDigest, Size: 1234}
	withSubject := marshalIndex(t, index.ImageIndex)

	dgst, err := makeManifestService(t, repo).Put(ctx, withSubject)
	if err != nil {
		t.Fatalf("failed to upload index: %v", err)
	}

	referrers := listReferrers(t, repo, subject.manifestDigest)
	if len(referrers) != 1 {
		t.Fatalf("expected 1 referrer, got %v", referrers)
	}
	_, payload, _ := withSubject.Payload()
	expected := v1.Descriptor{
		MediaType:    v1.MediaTypeImageIndex,
		Digest:       dgst,
		Size:         int64(len(payload)),
		ArtifactType: "application/vnd.example.index.v1",
		Annotations:  map[string]string{"org.example.name": "index"},
	}
	if !reflect.DeepEqual(referrers[0], expected) {
		t.Fatalf("unexpected descriptor: %#v, expected %#v", referrers[0], expected)
	}

	// the manifests of an index are not its referrers
	if referrers := listReferrers(t, repo, child.manifestDigest); len(referrers) != 0 {
		t.Fatalf("unexpected referrers of index child: %v", referrers)
	}
}

// TestReferrersTagSchema checks that manifests which are only listed in the
// index tagged following the referrers tag schema are listed as well.
func TestReferrersTagSchema(t *testing.T) {
	ctx := dcontext.Background()
	d := inmemory.New()
	registry := createRegistry(t, d)
	repo := makeRepository(t, registry, "referrers/tagschema")

	subject := uploadRandomOCIImage(t, repo)
	other := uploadRandomOCIImage(t, repo)

	indexed := uploadReferrer(t, repo, subject.manifestDigest, testReferrerArtifactType, "indexed")
	legacy := uploadReferrer(t, repo, subject.manifestDigest, testReferrerArtifactType, "legacy")
	foreign := uploadReferrer(t, repo, other.manifestDigest, testReferrerArtifactType, "foreign")

	// make the legacy referrer look like it was pushed before the referrers
	// have been indexed
	if err := NewVacuum(ctx, d).RemoveReferrerLink(repo.Named().Name(), subject.manifestDigest, legacy); err != nil {
		t.Fatalf("failed to remove referrer link: %v", err)
	}
	if referrers := listReferrers(t, repo, subject.manifestDigest); len(referrers) != 1 || referrers[0].Digest != indexed {
		t.Fatalf("unexpected referrers: %v", referrers)
	}

	descriptors := []v1.Descriptor{
		{MediaType: v1.MediaTypeImageManifest, Digest: indexed, Size: 1234},
		{MediaType: v1.MediaTypeImageManifest, Digest: legacy, Size: 1234},
		// entries with another subject, without a subject or which do not
		// exist have to be ignored
		{MediaType: v1.MediaTypeImageManifest, Digest: foreign, Size: 1234},
		{MediaType: v1.MediaTypeImageManifest, Digest: other.manifestDigest, Size: 1234},
		{MediaType: v1.MediaTypeImageManifest, Digest: digest.FromString("missing"), Size: 1234},
	}
	index, err := ocischema.FromDescriptors(descriptors, nil)
	if err != nil {
		t.Fatalf("failed to create index: %v", err)
	}
	// the tag schema index is maintained by clients and not verified
	manifests, err := repo.Manifests(ctx, SkipLayerVerification())
	if err != nil {
		t.Fatalf("failed to construct manifest service: %v", err)
	}
	indexDigest, err := manifests.Put(ctx, index)
	if err != nil {
		t.Fatalf("failed to upload index: %v", err)
	}
	tag := subject.manifestDigest.Algorithm().String() + "-" + subject.manifestDigest.Encoded()
	if err := repo.Tags(ctx).Tag(ctx, tag, v1.Descriptor{Digest: indexDigest}); err != nil {
		t.Fatalf("failed to tag index: %v", err)
	}

	referrers := listReferrers(t, repo, subject.manifestDigest)
	expected := map[digest.Digest]struct{}{indexed: {}, legacy: {}}
	if len(referrers) != 2 || !reflect.DeepEqual(referrerDigests(referrers), expected) {
		t.Fatalf("unexpected referrers: %v", referrers)
	}
}

func marshalIndex(t *testing.T, index ocischema.ImageIndex) *ocischema.DeserializedImageIndex {
	t.Helper()

	payload, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("failed to marshal index: %v", err)
	}
	var deserialized ocischema.DeserializedImageIndex
	if err := deserialized.UnmarshalJSON(payload); err != nil {
		t.Fatalf("failed to unmarshal index: %v", err)
	}

	return &deserialized
}
