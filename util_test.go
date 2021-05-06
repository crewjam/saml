package saml

import "testing"

func TestIsSameBase(t *testing.T) {
	type args struct {
		refURL  string
		someURL string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "both empty",
			args: args{},
			want: true},
		{name: "refURL empty",
			args: args{refURL: "", someURL: "https://some.work"},
			want: false},
		{name: "someURL empty",
			args: args{refURL: "https://some.work", someURL: ""},
			want: false},
		{name: "different schemes",
			args: args{refURL: "https://some.work", someURL: "http://some.work"},
			want: false},
		{name: "should match 1",
			args: args{refURL: "https://some.work", someURL: "https://some.work/a/b/c"},
			want: true},
		{name: "should match 2",
			args: args{refURL: "https://some.work/a/b/c", someURL: "https://some.work"},
			want: true},
		{name: "should match 3",
			args: args{refURL: "https://some.work/a/b/c", someURL: "https://some.work/1/2/3/4/5"},
			want: true},
		{name: "similar match",
			args: args{refURL: "https://some.work/", someURL: "https://some.work"},
			want: true},
		{name: "exact match",
			args: args{refURL: "https://some.work", someURL: "https://some.work"},
			want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSameBase(tt.args.refURL, tt.args.someURL); got != tt.want {
				t.Errorf("IsSameBase() = %v, want %v", got, tt.want)
			}
		})
	}
}
