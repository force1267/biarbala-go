package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/force1267/biarbala-go/pkg/config"
)

// Project represents a project in the database
type Project struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	ProjectID      string             `bson:"project_id"`
	ProjectName    string             `bson:"project_name"`
	UserID         string             `bson:"user_id,omitempty"`
	AccessPassword string             `bson:"access_password"`
	ProjectURL     string             `bson:"project_url"`
	Status         string             `bson:"status"`
	CreatedAt      time.Time          `bson:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at"`
	FileSize       int64              `bson:"file_size"`
	FileFormat     string             `bson:"file_format"`
	Settings       map[string]string  `bson:"settings,omitempty"`
	Domain         string             `bson:"domain,omitempty"`
	IsCustomDomain bool               `bson:"is_custom_domain"`
	DomainVerified bool               `bson:"domain_verified"`
}

// ProjectMetrics represents project metrics in the database
type ProjectMetrics struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	ProjectID      string             `bson:"project_id"`
	TotalRequests  int64              `bson:"total_requests"`
	TotalBandwidth int64              `bson:"total_bandwidth_bytes"`
	UniqueVisitors int64              `bson:"unique_visitors"`
	LastAccessed   time.Time          `bson:"last_accessed"`
	DailyMetrics   []DailyMetrics     `bson:"daily_metrics"`
	UpdatedAt      time.Time          `bson:"updated_at"`
}

// DailyMetrics represents daily metrics
type DailyMetrics struct {
	Date           time.Time `bson:"date"`
	Requests       int64     `bson:"requests"`
	BandwidthBytes int64     `bson:"bandwidth_bytes"`
	UniqueVisitors int64     `bson:"unique_visitors"`
}

// DomainVerification represents a domain verification challenge
type DomainVerification struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	ProjectID  string             `bson:"project_id"`
	Domain     string             `bson:"domain"`
	TXTRecord  string             `bson:"txt_record"`
	Verified   bool               `bson:"verified"`
	CreatedAt  time.Time          `bson:"created_at"`
	ExpiresAt  time.Time          `bson:"expires_at"`
	VerifiedAt *time.Time         `bson:"verified_at,omitempty"`
}

// MongoDBStorage implements storage interface using MongoDB
type MongoDBStorage struct {
	client   *mongo.Client
	database *mongo.Database
	config   *config.Config
}

// NewMongoDBStorage creates a new MongoDB storage instance
func NewMongoDBStorage(cfg *config.Config) (*MongoDBStorage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Database.MongoDB.Timeout)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.Database.MongoDB.URI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Test connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	database := client.Database(cfg.Database.MongoDB.Database)

	return &MongoDBStorage{
		client:   client,
		database: database,
		config:   cfg,
	}, nil
}

// CreateProject creates a new project
func (s *MongoDBStorage) CreateProject(ctx context.Context, project *Project) error {
	collection := s.database.Collection("projects")

	project.CreatedAt = time.Now()
	project.UpdatedAt = time.Now()

	_, err := collection.InsertOne(ctx, project)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	return nil
}

// GetProject retrieves a project by ID
func (s *MongoDBStorage) GetProject(ctx context.Context, projectID string) (*Project, error) {
	collection := s.database.Collection("projects")

	var project Project
	err := collection.FindOne(ctx, bson.M{"project_id": projectID}).Decode(&project)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("failed to get project: %w", err)
	}

	return &project, nil
}

// UpdateProject updates a project
func (s *MongoDBStorage) UpdateProject(ctx context.Context, projectID string, updates map[string]interface{}) error {
	collection := s.database.Collection("projects")

	updates["updated_at"] = time.Now()

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"project_id": projectID},
		bson.M{"$set": updates},
	)
	if err != nil {
		return fmt.Errorf("failed to update project: %w", err)
	}

	return nil
}

// DeleteProject deletes a project
func (s *MongoDBStorage) DeleteProject(ctx context.Context, projectID string) error {
	collection := s.database.Collection("projects")

	_, err := collection.DeleteOne(ctx, bson.M{"project_id": projectID})
	if err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}

	return nil
}

// ListProjects lists projects for a user
func (s *MongoDBStorage) ListProjects(ctx context.Context, userID string, page, pageSize int) ([]*Project, int64, error) {
	collection := s.database.Collection("projects")

	// Count total documents
	totalCount, err := collection.CountDocuments(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count projects: %w", err)
	}

	// Calculate skip value
	skip := (page - 1) * pageSize

	// Find projects
	opts := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{"created_at", -1}})

	cursor, err := collection.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list projects: %w", err)
	}
	defer cursor.Close(ctx)

	var projects []*Project
	if err := cursor.All(ctx, &projects); err != nil {
		return nil, 0, fmt.Errorf("failed to decode projects: %w", err)
	}

	return projects, totalCount, nil
}

// CreateProjectMetrics creates project metrics
func (s *MongoDBStorage) CreateProjectMetrics(ctx context.Context, metrics *ProjectMetrics) error {
	collection := s.database.Collection("project_metrics")

	metrics.UpdatedAt = time.Now()

	_, err := collection.InsertOne(ctx, metrics)
	if err != nil {
		return fmt.Errorf("failed to create project metrics: %w", err)
	}

	return nil
}

// UpdateProjectMetrics updates project metrics
func (s *MongoDBStorage) UpdateProjectMetrics(ctx context.Context, projectID string, updates map[string]interface{}) error {
	collection := s.database.Collection("project_metrics")

	updates["updated_at"] = time.Now()

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"project_id": projectID},
		bson.M{"$set": updates},
	)
	if err != nil {
		return fmt.Errorf("failed to update project metrics: %w", err)
	}

	return nil
}

// GetProjectMetrics retrieves project metrics
func (s *MongoDBStorage) GetProjectMetrics(ctx context.Context, projectID string) (*ProjectMetrics, error) {
	collection := s.database.Collection("project_metrics")

	var metrics ProjectMetrics
	err := collection.FindOne(ctx, bson.M{"project_id": projectID}).Decode(&metrics)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("project metrics not found")
		}
		return nil, fmt.Errorf("failed to get project metrics: %w", err)
	}

	return &metrics, nil
}

// RecordAccess records a project access for metrics
func (s *MongoDBStorage) RecordAccess(ctx context.Context, projectID string, bandwidth int64) error {
	collection := s.database.Collection("project_metrics")

	today := time.Now().Truncate(24 * time.Hour)

	// Update or create daily metrics
	_, err := collection.UpdateOne(
		ctx,
		bson.M{"project_id": projectID},
		bson.M{
			"$inc": bson.M{
				"total_requests":        1,
				"total_bandwidth_bytes": bandwidth,
			},
			"$set": bson.M{
				"last_accessed": time.Now(),
				"updated_at":    time.Now(),
			},
			"$push": bson.M{
				"daily_metrics": bson.M{
					"$each": []bson.M{{
						"date":            today,
						"requests":        1,
						"bandwidth_bytes": bandwidth,
						"unique_visitors": 0, // This would need more sophisticated tracking
					}},
					"$slice": -30, // Keep only last 30 days
				},
			},
		},
		options.Update().SetUpsert(true),
	)

	if err != nil {
		return fmt.Errorf("failed to record access: %w", err)
	}

	return nil
}

// CreateDomainVerification creates a new domain verification challenge
func (s *MongoDBStorage) CreateDomainVerification(ctx context.Context, verification *DomainVerification) error {
	collection := s.database.Collection("domain_verifications")

	_, err := collection.InsertOne(ctx, verification)
	if err != nil {
		return fmt.Errorf("failed to create domain verification: %w", err)
	}

	return nil
}

// GetDomainVerification retrieves a domain verification challenge
func (s *MongoDBStorage) GetDomainVerification(ctx context.Context, projectID, domain string) (*DomainVerification, error) {
	collection := s.database.Collection("domain_verifications")

	var verification DomainVerification
	err := collection.FindOne(ctx, bson.M{
		"project_id": projectID,
		"domain":     domain,
	}).Decode(&verification)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("domain verification not found")
		}
		return nil, fmt.Errorf("failed to get domain verification: %w", err)
	}

	return &verification, nil
}

// UpdateDomainVerification updates a domain verification challenge
func (s *MongoDBStorage) UpdateDomainVerification(ctx context.Context, projectID, domain string, updates map[string]interface{}) error {
	collection := s.database.Collection("domain_verifications")

	_, err := collection.UpdateOne(
		ctx,
		bson.M{
			"project_id": projectID,
			"domain":     domain,
		},
		bson.M{"$set": updates},
	)
	if err != nil {
		return fmt.Errorf("failed to update domain verification: %w", err)
	}

	return nil
}

// SetProjectDomain sets the domain for a project
func (s *MongoDBStorage) SetProjectDomain(ctx context.Context, projectID, domain string, isCustomDomain bool) error {
	updates := map[string]interface{}{
		"domain":           domain,
		"is_custom_domain": isCustomDomain,
		"domain_verified":  false, // Reset verification status when domain changes
	}

	return s.UpdateProject(ctx, projectID, updates)
}

// VerifyProjectDomain marks a project's domain as verified
func (s *MongoDBStorage) VerifyProjectDomain(ctx context.Context, projectID string) error {
	updates := map[string]interface{}{
		"domain_verified": true,
	}

	return s.UpdateProject(ctx, projectID, updates)
}

// GetProjectByDomain retrieves a project by its domain
func (s *MongoDBStorage) GetProjectByDomain(ctx context.Context, domain string) (*Project, error) {
	collection := s.database.Collection("projects")

	var project Project
	err := collection.FindOne(ctx, bson.M{"domain": domain}).Decode(&project)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("project not found for domain: %s", domain)
		}
		return nil, fmt.Errorf("failed to get project by domain: %w", err)
	}

	return &project, nil
}

// Close closes the MongoDB connection
// GetClient returns the MongoDB client
func (s *MongoDBStorage) GetClient() *mongo.Client {
	return s.client
}

func (s *MongoDBStorage) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}
