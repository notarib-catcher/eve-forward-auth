package database

import "eve-forward-auth/types"

func CheckPermissions(config *types.Config, charID string, corpID string, allianceID string) bool {

	allow := false
	for _, uid := range config.Overrides.Super_Admin_IDs {
		if uid == charID {
			allow = true
		}
	}

	for _, cid := range config.Overrides.Corp_Allow {
		if cid == corpID {
			allow = true
		}
	}

	for _, aid := range config.Overrides.Alliance_Allow {
		if aid == allianceID {
			allow = true
		}
	}

	return allow
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
