package types

type Config struct {
	Name       string
	App_ID     string
	App_Secret string
	Port       int

	Server struct {
		Domain             string
		Base_Domain        string
		Is_Secure          bool
		Prefix             string
		User_Header        string
		UID_Header         string
		Role_Header        string
		Redirect_Whitelist []string
	}

	Overrides struct {
		Super_Admin_IDs []string
		Alliance_Allow  []string
		Corp_Allow      []string
	}

	Database struct {
		Postgres_Connection_String string
		DB_Name                    string
		Default_Role               string
	}
}
