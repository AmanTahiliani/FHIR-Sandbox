package handlers

import (
	"testing"
)

func TestNormName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"  Jane  ", "jane"},
		{"SMITH", "smith"},
		{"", ""},
		{" Bob ", "bob"},
	}
	for _, tt := range tests {
		got := normName(tt.input)
		if got != tt.want {
			t.Errorf("normName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormSex(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"M", "M"},
		{"F", "F"},
		{"m", "M"},
		{"male", "M"},
		{"female", "F"},
		{"other", "O"},
		{"unknown", "U"},
		{"MALE", "M"},
		{"X", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := normSex(tt.input)
		if got != tt.want {
			t.Errorf("normSex(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestComputeMatchScore_AllMatch(t *testing.T) {
	a := map[string]string{
		"first_name": "jane",
		"last_name":  "smith",
		"email":      "j@test.com",
		"dob":        "1990-04-22",
		"sex":        "F",
	}
	score, fields := computeMatchScore(a, a)
	if score != 5 {
		t.Errorf("expected score=5, got %d", score)
	}
	for k, f := range fields {
		if !f.Match {
			t.Errorf("expected field %q to match", k)
		}
	}
}

func TestComputeMatchScore_NoneMatch(t *testing.T) {
	a := map[string]string{
		"first_name": "jane",
		"last_name":  "smith",
		"email":      "j@test.com",
		"dob":        "1990-04-22",
		"sex":        "F",
	}
	b := map[string]string{
		"first_name": "bob",
		"last_name":  "jones",
		"email":      "b@test.com",
		"dob":        "1985-01-01",
		"sex":        "M",
	}
	score, _ := computeMatchScore(a, b)
	if score != 0 {
		t.Errorf("expected score=0, got %d", score)
	}
}

func TestComputeMatchScore_EmptyDoesNotMatch(t *testing.T) {
	a := map[string]string{
		"first_name": "jane",
		"last_name":  "smith",
		"email":      "",
		"dob":        "",
		"sex":        "",
	}
	b := map[string]string{
		"first_name": "jane",
		"last_name":  "smith",
		"email":      "",
		"dob":        "",
		"sex":        "",
	}
	score, _ := computeMatchScore(a, b)
	if score != 2 {
		t.Errorf("expected score=2 (only name fields), got %d", score)
	}
}

func TestComputeMatchScore_PartialMatch(t *testing.T) {
	a := map[string]string{
		"first_name": "jane",
		"last_name":  "smith",
		"email":      "a@test.com",
		"dob":        "1990-04-22",
		"sex":        "F",
	}
	b := map[string]string{
		"first_name": "john",
		"last_name":  "smith",
		"email":      "b@test.com",
		"dob":        "1990-04-22",
		"sex":        "M",
	}
	score, fields := computeMatchScore(a, b)
	if score != 2 {
		t.Errorf("expected score=2 (last_name + dob), got %d", score)
	}
	if !fields["last_name"].Match {
		t.Error("expected last_name to match")
	}
	if !fields["dob"].Match {
		t.Error("expected dob to match")
	}
	if fields["first_name"].Match {
		t.Error("expected first_name to NOT match")
	}
}
