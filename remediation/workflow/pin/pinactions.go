package pin

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v40/github"
	metadata "github.com/nholuongut/secure-repo/remediation/workflow/metadata"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

func PinActions(inputYaml string) (string, bool, error) {
	workflow := metadata.Workflow{}
	updated := false
	err := yaml.Unmarshal([]byte(inputYaml), &workflow)
	if err != nil {
		return inputYaml, updated, fmt.Errorf("unable to parse yaml %v", err)
	}

	out := inputYaml

	for _, job := range workflow.Jobs {

		for _, step := range job.Steps {
			if len(step.Uses) > 0 {
				localUpdated := false
				out, localUpdated = PinAction(step.Uses, out)
				updated = updated || localUpdated
			}
		}
	}

	return out, updated, nil
}

func PinAction(action, inputYaml string) (string, bool) {

	updated := false
	if !strings.Contains(action, "@") || strings.HasPrefix(action, "docker://") {
		return inputYaml, updated // Cannot pin local actions and docker actions
	}

	if isAbsolute(action) {
		return inputYaml, updated
	}
	leftOfAt := strings.Split(action, "@")
	tagOrBranch := leftOfAt[1]

	splitOnSlash := strings.Split(leftOfAt[0], "/")
	owner := splitOnSlash[0]
	repo := splitOnSlash[1]

	PAT := os.Getenv("PAT")

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: PAT},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	commitSHA, _, err := client.Repositories.GetCommitSHA1(ctx, owner, repo, tagOrBranch, "")
	if err != nil {
		return inputYaml, updated
	}

	tagOrBranch, err = getSemanticVersion(client, owner, repo, tagOrBranch, commitSHA)
	if err != nil {
		return inputYaml, updated
	}

	pinnedAction := fmt.Sprintf("%s@%s # %s", leftOfAt[0], commitSHA, tagOrBranch)
	updated = !strings.EqualFold(action, pinnedAction)
	inputYaml = strings.ReplaceAll(inputYaml, action, pinnedAction)
	yamlWithPreviousActionCommentsRemoved, wasModified := removePreviousActionComments(pinnedAction, inputYaml)
	if wasModified {
		return yamlWithPreviousActionCommentsRemoved, updated
	}
	return inputYaml, updated
}

// It may be that there was already a comment next to the action
// In this case we want to remove the earlier comment
// we add a comment with the Action version so dependabot/ renovatebot can update it
// if there was no comment next to any action, updated will be false
func removePreviousActionComments(pinnedAction, inputYaml string) (string, bool) {
	updated := false
	stringParts := strings.Split(inputYaml, pinnedAction)
	if len(stringParts) > 1 {
		inputYaml = ""
		inputYaml = stringParts[0]
		for idx := 1; idx < len(stringParts); idx++ {
			trimmedString := strings.SplitN(stringParts[idx], "\n", 2)
			if len(trimmedString) > 1 {
				if strings.Contains(trimmedString[0], "#") {
					updated = true
				}
				inputYaml = inputYaml + pinnedAction + "\n" + trimmedString[1]
			}
		}
	}

	return inputYaml, updated
}

// https://github.com/sethvargo/ratchet/blob/3524c5cfde0439099b3a37274e683af4c779b0d1/parser/refs.go#L56
func isAbsolute(ref string) bool {
	parts := strings.Split(ref, "@")
	last := parts[len(parts)-1]

	if len(last) == 40 && isAllHex(last) {
		return true
	}

	if len(last) == 71 && last[:6] == "sha256" && isAllHex(last[7:]) {
		return true
	}

	return false
}

// isAllHex returns true if the given string is all hex characters, false
// otherwise.
func isAllHex(s string) bool {
	for _, ch := range s {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func getSemanticVersion(client *github.Client, owner, repo, tagOrBranch, commitSHA string) (string, error) {
	tags, _, err := client.Git.ListMatchingRefs(context.Background(), owner, repo, &github.ReferenceListOptions{
		Ref: fmt.Sprintf("tags/%s.", tagOrBranch),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	})
	if err != nil {
		return "", err
	}

	for i := len(tags) - 1; i >= 0; i-- {
		tag := strings.TrimPrefix(*tags[i].Ref, "refs/tags/")
		if *tags[i].Object.Type == "commit" {
			if commitSHA == *tags[i].Object.SHA {
				return tag, nil
			}
		} else {
			commitsha, _, err := client.Repositories.GetCommitSHA1(context.Background(), owner, repo, tag, "")
			if err != nil {
				return "", err
			}
			if commitSHA == commitsha {
				return tag, nil
			}
		}
	}
	return tagOrBranch, nil
}
