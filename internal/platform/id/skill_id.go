package id

const SkillIDLength = 17

// GenerateSkillID returns a 17-character alpha-numeric identifier.
func GenerateSkillID() (string, error) {
	return GenerateAlphaNumID(SkillIDLength)
}

// IsValidSkillID checks whether a skill ID matches the expected format.
func IsValidSkillID(v string) bool {
	if len(v) != SkillIDLength {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
