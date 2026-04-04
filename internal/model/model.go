package model

type Log struct {
	ID      string
	RawText string
}

type Error struct {
	LogID        string
	ErrorMessage string
	ErrorType    string
	Fingerprint  string
}
