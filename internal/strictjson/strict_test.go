package strictjson

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeRejectsDuplicateUnknownTrailingAndDeepJSON(t *testing.T) {
	type document struct {
		Value string `json:"value"`
	}
	for name, data := range map[string][]byte{
		"duplicate": []byte(`{"value":"a","value":"b"}`),
		"unknown":   []byte(`{"value":"a","other":true}`),
		"trailing":  []byte(`{"value":"a"}{}`),
		"deep":      []byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)),
	} {
		t.Run(name, func(t *testing.T) {
			var result document
			if err := Decode(data, &result, 64); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	var result document
	if err := Decode([]byte(`{"value":"a"}`), &result, 64); err != nil || result.Value != "a" {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestValidateAllowsBoundedNestedArrays(t *testing.T) {
	data := []byte(strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64))
	if err := Validate(data, 64); err != nil {
		t.Fatal(err)
	}
}
