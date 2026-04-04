package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"api-failure-analyzer/internal/db"
)

type App struct {
	ID        string
	Name      string
	APIKey    string
	CreatedAt interface{}
}

func CreateApp(ctx context.Context, name string) (*App, error) {
	apiKey := generateAPIKey()

	var appID string
	err := db.DB.QueryRow(ctx, `
		INSERT INTO apps (name, api_key)
		VALUES ($1, $2)
		RETURNING id
	`, name, apiKey).Scan(&appID)

	if err != nil {
		return nil, err
	}

	return &App{ID: appID, Name: name, APIKey: apiKey}, nil
}

func GetAppByAPIKey(ctx context.Context, apiKey string) (*App, error) {
	var app App
	err := db.DB.QueryRow(ctx, `
		SELECT id, name, api_key, created_at
		FROM apps
		WHERE api_key = $1
	`, apiKey).Scan(&app.ID, &app.Name, &app.APIKey, &app.CreatedAt)

	if err != nil {
		return nil, err
	}
	return &app, nil
}

func GetAppByID(ctx context.Context, appID string) (*App, error) {
	var app App
	err := db.DB.QueryRow(ctx, `
		SELECT id, name, api_key, created_at
		FROM apps
		WHERE id = $1
	`, appID).Scan(&app.ID, &app.Name, &app.APIKey, &app.CreatedAt)

	if err != nil {
		return nil, err
	}
	return &app, nil
}

func ListApps(ctx context.Context) ([]App, error) {
	rows, err := db.DB.Query(ctx, "SELECT id, name, api_key, created_at FROM apps ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Name, &a.APIKey, &a.CreatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, nil
}

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
