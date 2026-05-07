package id

import "testing"

func TestGenerateSkillIDFormat(t *testing.T) {
	v, err := GenerateSkillID()
	if err != nil {
		t.Fatalf("generate skill id: %v", err)
	}
	if len(v) != SkillIDLength {
		t.Fatalf("expected skill id length %d, got %d", SkillIDLength, len(v))
	}
	if !IsValidSkillID(v) {
		t.Fatalf("expected generated skill id valid, got %q", v)
	}
}

func TestGenerateSkillIDUniqueAcrossRuns(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		v, err := GenerateSkillID()
		if err != nil {
			t.Fatalf("generate skill id: %v", err)
		}
		if _, ok := seen[v]; ok {
			t.Fatalf("unexpected duplicate skill id %q", v)
		}
		seen[v] = struct{}{}
	}
}

func TestIsValidSkillIDRejectsBadValue(t *testing.T) {
	for _, tc := range []string{"", "short", "Ab3X9Kq1Lm8Pz2Rt*", "Ab3X9Kq1Lm8Pz2RtYY"} {
		if IsValidSkillID(tc) {
			t.Fatalf("expected invalid skill id rejected: %q", tc)
		}
	}
}
