package syftjson

import "testing"

func TestMetadataVendor(t *testing.T) {
	d, err := Parse([]byte(`{"artifacts":[
		{"name":"php-cli","type":"rpm","metadata":{"vendor":"GetPageSpeed LLC","epoch":null}},
		{"name":"a","metadata":{"vendor":7}},
		{"name":"b","metadata":["vendor"]},
		{"name":"c","metadata":"vendor"},
		{"name":"d","metadata":null},
		{"name":"e"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"GetPageSpeed LLC", "", "", "", "", ""}
	for i, a := range d.Artifacts {
		if a.Metadata.Vendor != want[i] {
			t.Errorf("%s: vendor %q, want %q", a.Name, a.Metadata.Vendor, want[i])
		}
	}
}
