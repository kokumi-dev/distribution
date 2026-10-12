package ocischema

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

var testSubject = v1.Descriptor{
	MediaType: v1.MediaTypeImageManifest,
	Digest:    "sha256:1a9ec845ee94c202b2d5da74a24f0ed2058318bfa9879fa541efaecba272e86b",
	Size:      985,
}

func TestSubjectRoundTrip(t *testing.T) {
	mfst, err := FromStruct(Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    v1.MediaTypeImageManifest,
		ArtifactType: "application/vnd.example.sbom.v1",
		Config:       v1.DescriptorEmptyJSON,
		Layers:       []v1.Descriptor{v1.DescriptorEmptyJSON},
		Subject:      &testSubject,
	})
	if err != nil {
		t.Fatalf("error creating manifest: %v", err)
	}
	_, payload, err := mfst.Payload()
	if err != nil {
		t.Fatalf("error getting payload: %v", err)
	}

	unmarshalled, _, err := distribution.UnmarshalManifest(v1.MediaTypeImageManifest, payload)
	if err != nil {
		t.Fatalf("error unmarshalling manifest: %v", err)
	}
	if subject := SubjectOf(unmarshalled); subject == nil || !reflect.DeepEqual(*subject, testSubject) {
		t.Fatalf("unexpected subject: %v", subject)
	}
	if artifactType := unmarshalled.(*DeserializedManifest).ArtifactType; artifactType != "application/vnd.example.sbom.v1" {
		t.Fatalf("unexpected artifactType: %q", artifactType)
	}
	for _, ref := range unmarshalled.References() {
		if ref.Digest == testSubject.Digest {
			t.Fatal("subject must not be part of the references")
		}
	}

	index, err := FromDescriptors(nil, nil)
	if err != nil {
		t.Fatalf("error creating index: %v", err)
	}
	index.ArtifactType = "application/vnd.example.index.v1"
	index.Subject = &testSubject
	payload, err = json.Marshal(index.ImageIndex)
	if err != nil {
		t.Fatalf("error marshalling index: %v", err)
	}

	unmarshalled, _, err = distribution.UnmarshalManifest(v1.MediaTypeImageIndex, payload)
	if err != nil {
		t.Fatalf("error unmarshalling index: %v", err)
	}
	if subject := SubjectOf(unmarshalled); subject == nil || !reflect.DeepEqual(*subject, testSubject) {
		t.Fatalf("unexpected subject: %v", subject)
	}
	if len(unmarshalled.References()) != 0 {
		t.Fatalf("subject must not be part of the references: %v", unmarshalled.References())
	}
}

func TestSubjectOmittedWhenUnset(t *testing.T) {
	mfst, err := FromStruct(Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    v1.DescriptorEmptyJSON,
	})
	if err != nil {
		t.Fatalf("error creating manifest: %v", err)
	}
	index, err := FromDescriptors(nil, nil)
	if err != nil {
		t.Fatalf("error creating index: %v", err)
	}

	for _, m := range []distribution.Manifest{mfst, index} {
		if subject := SubjectOf(m); subject != nil {
			t.Fatalf("unexpected subject: %v", subject)
		}
		_, payload, err := m.Payload()
		if err != nil {
			t.Fatalf("error getting payload: %v", err)
		}
		for _, field := range []string{"subject", "artifactType"} {
			if strings.Contains(string(payload), field) {
				t.Fatalf("%s must be omitted when unset: %s", field, payload)
			}
		}
	}

	if subject := SubjectOf(&schema2.DeserializedManifest{}); subject != nil {
		t.Fatalf("unexpected subject for schema2 manifest: %v", subject)
	}
}

func TestReferrerDescriptor(t *testing.T) {
	annotations := map[string]string{"org.example.key": "value"}

	for _, tc := range []struct {
		name                 string
		manifest             func() (distribution.Manifest, error)
		expectedMediaType    string
		expectedArtifactType string
	}{
		{
			name: "manifest with artifactType",
			manifest: func() (distribution.Manifest, error) {
				return FromStruct(Manifest{
					Versioned:    specs.Versioned{SchemaVersion: 2},
					MediaType:    v1.MediaTypeImageManifest,
					ArtifactType: "application/vnd.example.sbom.v1",
					Config:       v1.DescriptorEmptyJSON,
					Subject:      &testSubject,
					Annotations:  annotations,
				})
			},
			expectedMediaType:    v1.MediaTypeImageManifest,
			expectedArtifactType: "application/vnd.example.sbom.v1",
		},
		{
			name: "manifest without artifactType",
			manifest: func() (distribution.Manifest, error) {
				return FromStruct(Manifest{
					Versioned:   specs.Versioned{SchemaVersion: 2},
					MediaType:   v1.MediaTypeImageManifest,
					Config:      v1.Descriptor{MediaType: "application/vnd.example.config.v1+json", Digest: v1.DescriptorEmptyJSON.Digest, Size: 2},
					Subject:     &testSubject,
					Annotations: annotations,
				})
			},
			expectedMediaType:    v1.MediaTypeImageManifest,
			expectedArtifactType: "application/vnd.example.config.v1+json",
		},
		{
			name: "index with artifactType",
			manifest: func() (distribution.Manifest, error) {
				return indexFromStruct(ImageIndex{
					Versioned:    specs.Versioned{SchemaVersion: 2},
					MediaType:    v1.MediaTypeImageIndex,
					ArtifactType: "application/vnd.example.index.v1",
					Manifests:    []v1.Descriptor{},
					Subject:      &testSubject,
					Annotations:  annotations,
				})
			},
			expectedMediaType:    v1.MediaTypeImageIndex,
			expectedArtifactType: "application/vnd.example.index.v1",
		},
		{
			name: "index without artifactType",
			manifest: func() (distribution.Manifest, error) {
				return indexFromStruct(ImageIndex{
					Versioned:   specs.Versioned{SchemaVersion: 2},
					MediaType:   v1.MediaTypeImageIndex,
					Manifests:   []v1.Descriptor{},
					Subject:     &testSubject,
					Annotations: annotations,
				})
			},
			expectedMediaType:    v1.MediaTypeImageIndex,
			expectedArtifactType: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := tc.manifest()
			if err != nil {
				t.Fatalf("error creating manifest: %v", err)
			}
			_, payload, err := m.Payload()
			if err != nil {
				t.Fatalf("error getting payload: %v", err)
			}

			desc, err := ReferrerDescriptor(m)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expected := v1.Descriptor{
				MediaType:    tc.expectedMediaType,
				Digest:       digest.FromBytes(payload),
				Size:         int64(len(payload)),
				ArtifactType: tc.expectedArtifactType,
				Annotations:  annotations,
			}
			if !reflect.DeepEqual(desc, expected) {
				t.Fatalf("unexpected descriptor: %#v, expected %#v", desc, expected)
			}
		})
	}

	if _, err := ReferrerDescriptor(&schema2.DeserializedManifest{}); err == nil {
		t.Fatal("expected an error for a schema2 manifest")
	}
}

func indexFromStruct(ii ImageIndex) (*DeserializedImageIndex, error) {
	payload, err := json.Marshal(ii)
	if err != nil {
		return nil, err
	}
	var index DeserializedImageIndex
	return &index, index.UnmarshalJSON(payload)
}
