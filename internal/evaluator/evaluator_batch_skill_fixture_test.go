package evaluator

type batchSkillFixture struct {
	name        string
	description string
	files       []SourceFile
}

func newBatchSkillFixture(name, description string, files ...SourceFile) *Skill {
	return &Skill{
		Name:        name,
		Description: description,
		Files:       files,
	}
}

func skillDeclarationFile(content string) SourceFile {
	return SourceFile{Path: "SKILL.md", Language: "markdown", Content: content}
}

func skillReadmeFile(content string) SourceFile {
	return SourceFile{Path: "README.md", Language: "markdown", Content: content}
}

func skillPythonFile(path, content string) SourceFile {
	return SourceFile{Path: path, Language: "python", Content: content}
}

func skillShellFile(path, content string) SourceFile {
	return SourceFile{Path: path, Language: "bash", Content: content}
}

func skillTextFile(path, content string) SourceFile {
	return SourceFile{Path: path, Content: content}
}
