package ocischema

import (
	"fmt"

	"github.com/distribution/distribution/v3"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// SubjectOf returns the subject descriptor of the provided manifest, or nil
// if the manifest type does not support subjects or has none set.
func SubjectOf(m distribution.Manifest) *v1.Descriptor {
	switch m := m.(type) {
	case *DeserializedManifest:
		return m.Subject
	case *DeserializedImageIndex:
		return m.Subject
	}
	return nil
}

// ReferrerDescriptor returns the descriptor describing the provided manifest
// in a referrers listing of its subject. For image manifests without an
// artifactType, the artifactType is set to the config media type. The
// annotations of the manifest are carried over to the descriptor.
func ReferrerDescriptor(m distribution.Manifest) (v1.Descriptor, error) {
	var desc v1.Descriptor

	switch m := m.(type) {
	case *DeserializedManifest:
		desc.ArtifactType = m.ArtifactType
		if desc.ArtifactType == "" {
			desc.ArtifactType = m.Config.MediaType
		}
		desc.Annotations = m.Annotations
	case *DeserializedImageIndex:
		desc.ArtifactType = m.ArtifactType
		desc.Annotations = m.Annotations
	default:
		return v1.Descriptor{}, fmt.Errorf("manifest type %T cannot be a referrer", m)
	}

	mediaType, payload, err := m.Payload()
	if err != nil {
		return v1.Descriptor{}, err
	}

	desc.MediaType = mediaType
	desc.Digest = digest.FromBytes(payload)
	desc.Size = int64(len(payload))

	return desc, nil
}
