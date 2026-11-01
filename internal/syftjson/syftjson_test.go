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

func TestEnvValue(t *testing.T) {
	c := &ImageConfig{}
	c.Config.Env = []string{"PHP_VERSION=8.4.26", "EMPTY=", "NOVALUE", "PHP_VERSION=8.4.27", "A=b=c"}
	for name, want := range map[string]string{"PHP_VERSION": "8.4.27", "EMPTY": "", "A": "b=c"} {
		if got, ok := c.EnvValue(name); !ok || got != want {
			t.Errorf("%s: got %q, %v", name, got, ok)
		}
	}
	if _, ok := c.EnvValue("NOVALUE"); ok {
		t.Error("an entry without = isn't a variable")
	}
	var none *ImageConfig
	if _, ok := none.EnvValue("PHP_VERSION"); ok {
		t.Error("a missing config has no variables")
	}
}
