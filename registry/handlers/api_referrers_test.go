package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// pushReferrersTestBlob pushes the content as a blob to the repository and
// returns its descriptor.
func pushReferrersTestBlob(t *testing.T, env *testEnv, name reference.Named, mediaType string, content []byte) v1.Descriptor {
	t.Helper()

	dgst := digest.FromBytes(content)
	uploadURLBase, _ := startPushLayer(t, env, name)
	pushLayer(t, env.builder, name, dgst, uploadURLBase, bytes.NewReader(content))

	return v1.Descriptor{
		MediaType: mediaType,
		Digest:    dgst,
		Size:      int64(len(content)),
	}
}

// putReferrersTestManifest puts the manifest by the given reference, which
// is either a tag or empty to put it by digest, and returns the response
// together with the digest of the manifest.
func putReferrersTestManifest(t *testing.T, env *testEnv, name reference.Named, tag, mediaType string, manifest any) (*http.Response, digest.Digest) {
	t.Helper()

	// the payload sent by putManifest
	payload, err := json.MarshalIndent(manifest, "", "   ")
	if err != nil {
		t.Fatalf("unexpected error marshaling manifest: %v", err)
	}
	dgst := digest.FromBytes(payload)

	var ref reference.Named
	if tag != "" {
		ref, err = reference.WithTag(name, tag)
	} else {
		ref, err = reference.WithDigest(name, dgst)
	}
	if err != nil {
		t.Fatalf("unexpected error creating reference: %v", err)
	}
	manifestURL, err := env.builder.BuildManifestURL(ref)
	if err != nil {
		t.Fatalf("unexpected error building manifest url: %v", err)
	}

	return putManifest(t, "putting manifest", manifestURL, mediaType, manifest), dgst
}

// getReferrers gets the referrers of the subject, checks the response to be a
// well formed image index and returns it together with the response headers.
func getReferrers(t *testing.T, env *testEnv, name reference.Named, subject digest.Digest, values ...url.Values) (http.Header, v1.Index) {
	t.Helper()

	referrersURL, err := env.builder.BuildReferrersURL(name, subject, values...)
	if err != nil {
		t.Fatalf("unexpected error building referrers url: %v", err)
	}
	resp, err := http.Get(referrersURL)
	if err != nil {
		t.Fatalf("unexpected error getting referrers: %v", err)
	}
	defer resp.Body.Close()

	checkResponse(t, "getting referrers", resp, http.StatusOK)
	checkHeaders(t, resp, http.Header{
		"Content-Type":   []string{v1.MediaTypeImageIndex},
		"Content-Length": []string{"*"},
	})

	// the list of manifests must be present even if it is empty
	var raw map[string]json.RawMessage
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatalf("unexpected error reading referrers: %v", err)
	}
	if err := json.Unmarshal(body.Bytes(), &raw); err != nil {
		t.Fatalf("unexpected error decoding referrers: %v", err)
	}
	if manifests := string(raw["manifests"]); len(manifests) == 0 || manifests[0] != '[' {
		t.Fatalf("manifests is not a list: %q", manifests)
	}

	var index v1.Index
	if err := json.Unmarshal(body.Bytes(), &index); err != nil {
		t.Fatalf("unexpected error decoding referrers: %v", err)
	}
	if index.SchemaVersion != 2 || index.MediaType != v1.MediaTypeImageIndex {
		t.Fatalf("unexpected index: schemaVersion=%d, mediaType=%q", index.SchemaVersion, index.MediaType)
	}

	return resp.Header, index
}

func TestReferrersAPI(t *testing.T) {
	env := newTestEnv(t, true)
	defer env.Shutdown()

	imageName, err := reference.WithName("foo/referrers")
	if err != nil {
		t.Fatalf("unable to parse reference: %v", err)
	}

	const (
		sbomType      = "application/vnd.example.sbom.v1"
		signatureType = "application/vnd.example.signature.v1+json"
		indexType     = "application/vnd.example.index.v1"
	)

	// nothing has been pushed to the repository yet
	header, index := getReferrers(t, env, imageName, digest.FromString("unknown"))
	if len(index.Manifests) != 0 {
		t.Fatalf("unexpected referrers in empty repository: %v", index.Manifests)
	}
	if filters := header.Values("OCI-Filters-Applied"); len(filters) != 0 {
		t.Fatalf("unexpected OCI-Filters-Applied header: %v", filters)
	}

	emptyConfig := pushReferrersTestBlob(t, env, imageName, v1.MediaTypeEmptyJSON, []byte("{}"))
	signatureConfig := emptyConfig
	signatureConfig.MediaType = signatureType
	layer := pushReferrersTestBlob(t, env, imageName, v1.MediaTypeImageLayer, []byte("layer"))

	// the subject is put after its first referrer
	subject := ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    emptyConfig,
		Layers:    []v1.Descriptor{layer},
	}
	subjectPayload, err := json.MarshalIndent(subject, "", "   ")
	if err != nil {
		t.Fatalf("unexpected error marshaling subject: %v", err)
	}
	subjectDesc := v1.Descriptor{
		MediaType: v1.MediaTypeImageManifest,
		Digest:    digest.FromBytes(subjectPayload),
		Size:      int64(len(subjectPayload)),
	}

	expected := make(map[digest.Digest]v1.Descriptor)
	put := func(tag, mediaType string, manifest any, artifactType string, annotations map[string]string) digest.Digest {
		t.Helper()

		resp, dgst := putReferrersTestManifest(t, env, imageName, tag, mediaType, manifest)
		defer resp.Body.Close()
		checkResponse(t, "putting referrer", resp, http.StatusCreated)
		checkHeaders(t, resp, http.Header{
			"Docker-Content-Digest": []string{dgst.String()},
			"OCI-Subject":           []string{subjectDesc.Digest.String()},
		})

		payload, _ := json.MarshalIndent(manifest, "", "   ")
		expected[dgst] = v1.Descriptor{
			MediaType:    mediaType,
			Digest:       dgst,
			Size:         int64(len(payload)),
			ArtifactType: artifactType,
			Annotations:  annotations,
		}

		return dgst
	}

	// an artifact put by digest before the subject exists
	sbom := put("", v1.MediaTypeImageManifest, ocischema.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    v1.MediaTypeImageManifest,
		ArtifactType: sbomType,
		Config:       emptyConfig,
		Layers:       []v1.Descriptor{layer},
		Subject:      &subjectDesc,
		Annotations:  map[string]string{"org.example.name": "sbom"},
	}, sbomType, map[string]string{"org.example.name": "sbom"})

	_, index = getReferrers(t, env, imageName, subjectDesc.Digest)
	if len(index.Manifests) != 1 || index.Manifests[0].Digest != sbom {
		t.Fatalf("unexpected referrers of missing subject: %v", index.Manifests)
	}

	resp, _ := putReferrersTestManifest(t, env, imageName, "subject", v1.MediaTypeImageManifest, subject)
	resp.Body.Close()
	checkResponse(t, "putting subject", resp, http.StatusCreated)
	if values := resp.Header.Values("OCI-Subject"); len(values) != 0 {
		t.Fatalf("unexpected OCI-Subject header for manifest without subject: %v", values)
	}

	// an artifact without artifactType put by tag, falls back to the media
	// type of the config
	put("signature", v1.MediaTypeImageManifest, ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    signatureConfig,
		Layers:    []v1.Descriptor{layer},
		Subject:   &subjectDesc,
	}, signatureType, nil)

	// another artifact of the same type as the first one
	put("", v1.MediaTypeImageManifest, ocischema.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    v1.MediaTypeImageManifest,
		ArtifactType: sbomType,
		Config:       emptyConfig,
		Layers:       []v1.Descriptor{layer},
		Subject:      &subjectDesc,
		Annotations:  map[string]string{"org.example.name": "another sbom"},
	}, sbomType, map[string]string{"org.example.name": "another sbom"})

	// an index with a subject
	indexReferrer := put("", v1.MediaTypeImageIndex, ocischema.ImageIndex{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    v1.MediaTypeImageIndex,
		ArtifactType: indexType,
		Manifests:    []v1.Descriptor{{MediaType: v1.MediaTypeImageManifest, Digest: sbom, Size: expected[sbom].Size}},
		Subject:      &subjectDesc,
		Annotations:  map[string]string{"org.example.name": "index"},
	}, indexType, map[string]string{"org.example.name": "index"})

	// putting a referrer again must not list it twice
	put("", v1.MediaTypeImageManifest, ocischema.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    v1.MediaTypeImageManifest,
		ArtifactType: sbomType,
		Config:       emptyConfig,
		Layers:       []v1.Descriptor{layer},
		Subject:      &subjectDesc,
		Annotations:  map[string]string{"org.example.name": "sbom"},
	}, sbomType, map[string]string{"org.example.name": "sbom"})

	checkReferrers := func(msg string, values url.Values, filtered bool, expected map[digest.Digest]v1.Descriptor) {
		t.Helper()

		header, index := getReferrers(t, env, imageName, subjectDesc.Digest, values)
		if filtered {
			if filters := header.Values("OCI-Filters-Applied"); !reflect.DeepEqual(filters, []string{"artifactType"}) {
				t.Fatalf("%s: unexpected OCI-Filters-Applied header: %v", msg, filters)
			}
		} else if filters := header.Values("OCI-Filters-Applied"); len(filters) != 0 {
			t.Fatalf("%s: unexpected OCI-Filters-Applied header: %v", msg, filters)
		}

		actual := make(map[digest.Digest]v1.Descriptor, len(index.Manifests))
		for _, desc := range index.Manifests {
			actual[desc.Digest] = desc
		}
		if len(index.Manifests) != len(expected) || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s: unexpected referrers: %#v, expected %#v", msg, index.Manifests, expected)
		}
	}

	if len(expected) != 4 {
		t.Fatalf("expected 4 distinct referrers, got %d", len(expected))
	}
	checkReferrers("all referrers", nil, false, expected)

	byType := func(artifactType string) map[digest.Digest]v1.Descriptor {
		filtered := make(map[digest.Digest]v1.Descriptor)
		for dgst, desc := range expected {
			if desc.ArtifactType == artifactType {
				filtered[dgst] = desc
			}
		}
		return filtered
	}
	for artifactType, count := range map[string]int{sbomType: 2, signatureType: 1, indexType: 1, "application/vnd.example.unknown": 0} {
		filtered := byType(artifactType)
		if len(filtered) != count {
			t.Fatalf("expected %d referrers of type %s, got %d", count, artifactType, len(filtered))
		}
		checkReferrers("referrers of type "+artifactType, url.Values{"artifactType": []string{artifactType}}, true, filtered)
	}

	// the referrers of a referrer are not the referrers of its subject
	_, index = getReferrers(t, env, imageName, sbom)
	if len(index.Manifests) != 0 {
		t.Fatalf("unexpected referrers of referrer: %v", index.Manifests)
	}

	// a deleted referrer is not listed anymore
	ref, _ := reference.WithDigest(imageName, indexReferrer)
	manifestURL, err := env.builder.BuildManifestURL(ref)
	if err != nil {
		t.Fatalf("unexpected error building manifest url: %v", err)
	}
	resp, err = httpDelete(manifestURL)
	if err != nil {
		t.Fatalf("unexpected error deleting manifest: %v", err)
	}
	resp.Body.Close()
	checkResponse(t, "deleting referrer", resp, http.StatusAccepted)

	delete(expected, indexReferrer)
	checkReferrers("referrers after delete", nil, false, expected)
}

func TestReferrersAPIInvalidRequests(t *testing.T) {
	env := newTestEnv(t, true)
	defer env.Shutdown()

	imageName, err := reference.WithName("foo/referrers")
	if err != nil {
		t.Fatalf("unable to parse reference: %v", err)
	}

	for _, invalid := range []string{"notadigest", "sha256:tooshort", "latest"} {
		referrersURL, err := env.builder.BuildReferrersURL(imageName, digest.Digest(invalid))
		if err != nil {
			t.Fatalf("unexpected error building referrers url: %v", err)
		}
		resp, err := http.Get(referrersURL)
		if err != nil {
			t.Fatalf("unexpected error getting referrers: %v", err)
		}
		checkResponse(t, "getting referrers of invalid digest "+invalid, resp, http.StatusBadRequest)
		checkBodyHasErrorCodes(t, "getting referrers of invalid digest "+invalid, resp, errcode.ErrorCodeDigestInvalid)
		resp.Body.Close()
	}

	// only reading the referrers is supported
	referrersURL, err := env.builder.BuildReferrersURL(imageName, digest.FromString("subject"))
	if err != nil {
		t.Fatalf("unexpected error building referrers url: %v", err)
	}
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		req, err := http.NewRequest(method, referrersURL, nil)
		if err != nil {
			t.Fatalf("unexpected error creating request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("unexpected error doing %s request: %v", method, err)
		}
		resp.Body.Close()
		checkResponse(t, method+" on referrers", resp, http.StatusMethodNotAllowed)
	}

	// a manifest with an invalid subject is rejected
	config := pushReferrersTestBlob(t, env, imageName, v1.MediaTypeEmptyJSON, []byte("{}"))
	resp, dgst := putReferrersTestManifest(t, env, imageName, "", v1.MediaTypeImageManifest, ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    config,
		Layers:    []v1.Descriptor{},
		Subject:   &v1.Descriptor{MediaType: v1.MediaTypeImageManifest, Digest: "sha256:invalid", Size: 2},
	})
	defer resp.Body.Close()
	checkResponse(t, "putting manifest with invalid subject", resp, http.StatusBadRequest)
	checkBodyHasErrorCodes(t, "putting manifest with invalid subject", resp, errcode.ErrorCodeDigestInvalid)
	if values := resp.Header.Values("OCI-Subject"); len(values) != 0 {
		t.Fatalf("unexpected OCI-Subject header: %v", values)
	}

	ref, _ := reference.WithDigest(imageName, dgst)
	manifestURL, err := env.builder.BuildManifestURL(ref)
	if err != nil {
		t.Fatalf("unexpected error building manifest url: %v", err)
	}
	resp, err = http.Get(manifestURL)
	if err != nil {
		t.Fatalf("unexpected error getting manifest: %v", err)
	}
	defer resp.Body.Close()
	checkResponse(t, "getting rejected manifest", resp, http.StatusNotFound)
}

// TestReferrersAPIPullThroughCache checks that a pull through cache responds
// as if the referrers API does not exist, as clients are expected to fall
// back to the referrers tag schema then.
func TestReferrersAPIPullThroughCache(t *testing.T) {
	env := newTestEnvMirror(t, true)
	defer env.Shutdown()

	imageName, err := reference.WithName("foo/referrers")
	if err != nil {
		t.Fatalf("unable to parse reference: %v", err)
	}

	referrersURL, err := env.builder.BuildReferrersURL(imageName, digest.FromString("subject"))
	if err != nil {
		t.Fatalf("unexpected error building referrers url: %v", err)
	}
	resp, err := http.Get(referrersURL)
	if err != nil {
		t.Fatalf("unexpected error getting referrers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected status getting referrers from pull through cache: %v", resp.StatusCode)
	}
}
