package wgconf

import "amneziawg-web-ui/web-ui/api"

// MergeISettings layers overrides over whatever came before, earliest first,
// so a later layer wins. An empty value in a layer does not clear the key:
// the form sends every field, and an untouched one arrives blank. There is
// no shipped default layer - a client's own generated chain
// (api.GenerateISettings) is the caller's first layer, since one shared I1
// across every deployment was a template an observer could match on.
func MergeISettings(layers ...map[string]string) api.ISettings {
	out := api.ISettings{"i1": "", "i2": "", "i3": "", "i4": "", "i5": ""}
	for _, layer := range layers {
		for k, v := range layer {
			if v != "" {
				out[k] = v
			}
		}
	}
	return out
}
