package database

import "eve-forward-auth/types"

func CheckPermissionsAndGetMinimumRole(config *types.Config, charID string, corpID string, allianceID string) (bool, string) {
	guestMode := config.Overrides.Guest_Role == ""

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

	if !allow {
		if guestMode {
			//allow as guest
			return true, config.Overrides.Guest_Role
		} else {
			//deny with no role
			return false, ""
		}
	}

	//allow as member
	return allow, config.Database.Default_Role

}
