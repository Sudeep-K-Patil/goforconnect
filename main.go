package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	client               *mongo.Client
	profilesCollection   *mongo.Collection
	usersCollection      *mongo.Collection
	jobsCollection       *mongo.Collection
	workStatusCollection *mongo.Collection
	leetcodeProfilesCollection *mongo.Collection
)

type User struct {
	Username  string    `json:"username" bson:"username"`
	Email     string    `json:"email" bson:"email"`
	Password  string    `json:"password" bson:"password"`
	Role      string    `json:"role" bson:"role"`
	CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
}

type SeekerProfile struct {
	FullName     string   `json:"fullName" bson:"fullName"`
	Email        string   `json:"email" bson:"email"`
	Title        string   `json:"title" bson:"title"`
	Bio          string   `json:"bio" bson:"bio"`
	Skills       []string `json:"skills" bson:"skills"`
	Experience   string   `json:"experience" bson:"experience"`
	Education    string   `json:"education" bson:"education"`
	LinkedInURL  string   `json:"linkedInURL" bson:"linkedInURL"`
	Type         string   `json:"type" bson:"type"`
	CreatedAt    time.Time `json:"createdAt" bson:"createdAt"`
}

type RecruiterProfile struct {
	FullName            string    `json:"fullName" bson:"fullName"`
	Email               string    `json:"email" bson:"email"`
	CompanyName         string    `json:"companyName" bson:"companyName"`
	Position            string    `json:"position" bson:"position"`
	CompanyDescription  string    `json:"companyDescription" bson:"companyDescription"`
	Type                string    `json:"type" bson:"type"`
	CreatedAt           time.Time `json:"createdAt" bson:"createdAt"`
}

type Job struct {
	ID             string    `json:"id" bson:"_id"`
	Title          string    `json:"title" bson:"title"`
	Company        string    `json:"company" bson:"company"`
	Description    string    `json:"description" bson:"description"`
	RequiredSkills []string  `json:"requiredSkills" bson:"requiredSkills"`
	Location       string    `json:"location" bson:"location"`
	PostedDate     time.Time `json:"postedDate" bson:"postedDate"`
	SalaryRange    struct {
		Min float64 `json:"min" bson:"min"`
		Max float64 `json:"max" bson:"max"`
	} `json:"salaryRange" bson:"salaryRange"`
	ExperienceLevel string `json:"experienceLevel" bson:"experienceLevel"`
}

type LeetCodeProfile struct {
	Username         string  `json:"username" bson:"username"`
	Ranking          int     `json:"ranking" bson:"ranking"`
	TotalSolved      int     `json:"totalSolved" bson:"totalSolved"`
	EasySolved       int     `json:"easySolved" bson:"easySolved"`
	MediumSolved     int     `json:"mediumSolved" bson:"mediumSolved"`
	HardSolved       int     `json:"hardSolved" bson:"hardSolved"`
	AcceptanceRate   float64 `json:"acceptanceRate" bson:"acceptanceRate"`
	ContributionRank int     `json:"contributionRank" bson:"contributionRank"`
	Reputation       int     `json:"reputation" bson:"reputation"`
	CreatedAt        time.Time `json:"createdAt" bson:"createdAt"`
}

type WorkStatus struct {
	UserID         string    `json:"userId" bson:"userId"`
	Email          string    `json:"email" bson:"email"`
	CurrentStatus  string    `json:"currentStatus" bson:"currentStatus"` // "Working", "Open to Work", "Freelancing", etc.
	JobTitle       string    `json:"jobTitle" bson:"jobTitle"`
	Company        string    `json:"company" bson:"company"`
	AvailableHours int       `json:"availableHours" bson:"availableHours"`
	Skills         []string  `json:"skills" bson:"skills"`
	Availability   struct {
		StartDate     time.Time `json:"startDate" bson:"startDate"`
		EndDate       time.Time `json:"endDate" bson:"endDate"`
		IsFullTime    bool      `json:"isFullTime" bson:"isFullTime"`
		PreferredRole string    `json:"preferredRole" bson:"preferredRole"`
	} `json:"availability" bson:"availability"`
	CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt" bson:"updatedAt"`
}

type MatchingJob struct {
	Title            string   `json:"title"`
	Company          string   `json:"company"`
	RequiredSkills   []string `json:"requiredSkills"`
	ExperienceLevel  string   `json:"experienceLevel"`
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

    // Handle preflight requests
    if r.Method == "OPTIONS" {
        w.WriteHeader(http.StatusOK)
        return
    }

    // Only accept POST requests
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse JSON request body
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        log.Printf("Error decoding signup request: %v", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate input fields
    if user.Username == "" {
        http.Error(w, "Username is required", http.StatusBadRequest)
        return
    }

    if user.Email == "" {
        http.Error(w, "Email is required", http.StatusBadRequest)
        return
    }

    // Email validation regex
    emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
    if !emailRegex.MatchString(user.Email) {
        http.Error(w, "Invalid email format", http.StatusBadRequest)
        return
    }

    if user.Password == "" {
        http.Error(w, "Password is required", http.StatusBadRequest)
        return
    }

    // Password strength validation
    if len(user.Password) < 8 {
        http.Error(w, "Password must be at least 8 characters long", http.StatusBadRequest)
        return
    }

    // Set default role if not provided
    if user.Role == "" {
        user.Role = "seeker"
    }

    // Validate role
    validRoles := map[string]bool{
        "seeker": true,
        "recruiter": true,
        "admin": true,
    }
    if !validRoles[user.Role] {
        http.Error(w, "Invalid user role", http.StatusBadRequest)
        return
    }

    // Hash password
    hashedPassword, err := hashPassword(user.Password)
    if err != nil {
        log.Printf("Error hashing password: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Replace plain text password with hashed password
    user.Password = hashedPassword
    user.CreatedAt = time.Now()

    // Attempt to insert user into database
    _, err = usersCollection.InsertOne(context.TODO(), user)
    if err != nil {
        // Check for duplicate key error (unique email constraint)
        if mongo.IsDuplicateKeyError(err) {
            log.Printf("Signup attempt with existing email: %s", user.Email)
            http.Error(w, "Email already registered", http.StatusConflict)
            return
        }

        // Log other potential database errors
        log.Printf("Database insertion error: %v", err)
        http.Error(w, "Failed to create user", http.StatusInternalServerError)
        return
    }

    // Log successful signup
    log.Printf("User signup successful: %s (%s)", user.Username, user.Email)

    // Prepare response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "User registered successfully",
        "username": user.Username,
        "email": user.Email,
    })
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginUser User
	err := json.NewDecoder(r.Body).Decode(&loginUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate input
	if loginUser.Email == "" || loginUser.Password == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Find user
	var user User
	err = usersCollection.FindOne(context.TODO(), bson.M{"email": loginUser.Email}).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check password
	if !checkPasswordHash(loginUser.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create response
	token := "dummy-token-" + user.Email
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user": map[string]string{
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
	})
}

func saveSeekerProfileHandler(w http.ResponseWriter, r *http.Request) {
	var seekerProfile SeekerProfile
	err := json.NewDecoder(r.Body).Decode(&seekerProfile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate input
	if seekerProfile.FullName == "" || seekerProfile.Title == "" || seekerProfile.Bio == "" || len(seekerProfile.Skills) == 0 {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Get email from token
	email := r.Header.Get("Authorization")
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	seekerProfile.Email = strings.TrimPrefix(email, "dummy-token-")
	seekerProfile.Type = "developer"
	seekerProfile.CreatedAt = time.Now()

	// Save to database
	_, err = profilesCollection.InsertOne(context.TODO(), seekerProfile)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			http.Error(w, "Profile already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Developer profile saved successfully",
		"email":   seekerProfile.Email,
	})
}

func saveRecruiterProfileHandler(w http.ResponseWriter, r *http.Request) {
	var recruiterProfile RecruiterProfile
	err := json.NewDecoder(r.Body).Decode(&recruiterProfile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate input
	if recruiterProfile.FullName == "" || recruiterProfile.CompanyName == "" || recruiterProfile.Position == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Get email from token
	email := r.Header.Get("Authorization")
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	recruiterProfile.Email = strings.TrimPrefix(email, "dummy-token-")
	recruiterProfile.Type = "recruiter"
	recruiterProfile.CreatedAt = time.Now()

	// Save to database
	_, err = profilesCollection.InsertOne(context.TODO(), recruiterProfile)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			http.Error(w, "Profile already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Recruiter profile saved successfully",
		"email":   recruiterProfile.Email,
	})
}

func initDB() error {
    // MongoDB connection setup
    mongoURI := "mongodb://localhost:27017"
    log.Printf("Attempting to connect to MongoDB at: %s", mongoURI)

    clientOptions := options.Client().ApplyURI(mongoURI)

    var err error
    client, err = mongo.Connect(context.TODO(), clientOptions)
    if err != nil {
        log.Printf("Failed to connect to MongoDB: %v", err)
        return fmt.Errorf("failed to connect to MongoDB: %v", err)
    }

    log.Println("MongoDB connection established successfully")

    err = client.Ping(context.TODO(), nil)
    if err != nil {
        log.Printf("Failed to ping MongoDB: %v", err)
        return fmt.Errorf("failed to ping MongoDB: %v", err)
    }

    log.Println("Successfully pinged MongoDB")

    database := client.Database("devconnect")
    log.Printf("Using database: %s", database.Name())

    // Explicitly create collections with validation
    collections := []string{
        "users", 
        "profiles", 
        "jobs", 
        "work_status", 
        "leetcode_profiles",
    }

    for _, collectionName := range collections {
        err = createCollectionIfNotExists(database, collectionName)
        if err != nil {
            log.Printf("Failed to create collection %s: %v", collectionName, err)
            return fmt.Errorf("failed to create collection %s: %v", collectionName, err)
        }
        log.Printf("Collection created/verified: %s", collectionName)
    }

    // Assign global collection variables
    profilesCollection = database.Collection("profiles")
    usersCollection = database.Collection("users")
    jobsCollection = database.Collection("jobs")
    workStatusCollection = database.Collection("work_status")
    leetcodeProfilesCollection = database.Collection("leetcode_profiles")

    // Create indexes
    indexModels := []mongo.IndexModel{
        {
            Keys:    bson.D{{"email", 1}},
            Options: options.Index().SetUnique(true),
        },
        {
            Keys:    bson.D{{"requiredSkills", 1}},
            Options: options.Index(),
        },
        {
            Keys:    bson.D{{"userId", 1}},
            Options: options.Index(),
        },
        {
            Keys:    bson.D{{"currentStatus", 1}},
            Options: options.Index(),
        },
    }

    // Create unique index for email in users collection
    _, err = usersCollection.Indexes().CreateOne(
        context.TODO(), 
        mongo.IndexModel{
            Keys: bson.D{{"email", 1}},
            Options: options.Index().SetUnique(true),
        },
    )
    if err != nil {
        log.Printf("Failed to create unique email index: %v", err)
        return fmt.Errorf("failed to create unique email index: %v", err)
    }

    log.Println("Database initialization completed successfully")
    return nil
}

func createCollectionIfNotExists(database *mongo.Database, collectionName string) error {
    // List existing collections
    collections, err := database.ListCollectionNames(context.TODO(), bson.D{})
    if err != nil {
        return err
    }

    // Check if collection already exists
    for _, existingCollection := range collections {
        if existingCollection == collectionName {
            return nil  // Collection already exists
        }
    }

    // Create collection
    err = database.CreateCollection(context.TODO(), collectionName)
    if err != nil {
        return err
    }

    // Optional: Add validation rules for specific collections
    switch collectionName {
    case "users":
        return addUserCollectionValidation(database)
    case "jobs":
        return addJobCollectionValidation(database)
    case "work_status":
        return addWorkStatusCollectionValidation(database)
    default:
        return nil
    }
}

func addUserCollectionValidation(database *mongo.Database) error {
    validator := bson.M{
        "$jsonSchema": bson.M{
            "bsonType": "object",
            "required": []string{"email", "password", "role"},
            "properties": bson.M{
                "email": bson.M{
                    "bsonType":    "string",
                    "description": "must be a string and is required",
                },
                "password": bson.M{
                    "bsonType":    "string",
                    "description": "must be a string and is required",
                },
                "role": bson.M{
                    "enum":        []string{"seeker", "recruiter", "admin"},
                    "description": "can only be one of the enum values",
                },
            },
        },
    }

    return database.RunCommand(context.TODO(), bson.D{
        {"collMod", "users"},
        {"validator", validator},
        {"validationLevel", "strict"},
    }).Err()
}

func addJobCollectionValidation(database *mongo.Database) error {
    validator := bson.M{
        "$jsonSchema": bson.M{
            "bsonType": "object",
            "required": []string{"title", "company", "requiredSkills"},
            "properties": bson.M{
                "title": bson.M{
                    "bsonType":    "string",
                    "description": "must be a string and is required",
                },
                "company": bson.M{
                    "bsonType":    "string",
                    "description": "must be a string and is required",
                },
                "requiredSkills": bson.M{
                    "bsonType":    "array",
                    "description": "must be an array of strings",
                    "items": bson.M{
                        "bsonType": "string",
                    },
                },
            },
        },
    }

    return database.RunCommand(context.TODO(), bson.D{
        {"collMod", "jobs"},
        {"validator", validator},
        {"validationLevel", "strict"},
    }).Err()
}

func addWorkStatusCollectionValidation(database *mongo.Database) error {
    validator := bson.M{
        "$jsonSchema": bson.M{
            "bsonType": "object",
            "required": []string{"userId", "currentStatus"},
            "properties": bson.M{
                "userId": bson.M{
                    "bsonType":    "string",
                    "description": "must be a string and is required",
                },
                "currentStatus": bson.M{
                    "enum":        []string{"Open to Work", "Working", "Freelancing", "Studying"},
                    "description": "can only be one of the enum values",
                },
                "skills": bson.M{
                    "bsonType":    "array",
                    "description": "must be an array of strings",
                    "items": bson.M{
                        "bsonType": "string",
                    },
                },
            },
        },
    }

    return database.RunCommand(context.TODO(), bson.D{
        {"collMod", "work_status"},
        {"validator", validator},
        {"validationLevel", "strict"},
    }).Err()
}

func createJobHandler(w http.ResponseWriter, r *http.Request) {
	var job Job
	err := json.NewDecoder(r.Body).Decode(&job)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate job input
	if job.Title == "" || job.Company == "" || len(job.RequiredSkills) == 0 {
		http.Error(w, "Invalid job details", http.StatusBadRequest)
		return
	}

	job.PostedDate = time.Now()
	
	// Insert job
	_, err = jobsCollection.InsertOne(context.TODO(), job)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Job created successfully"})
}

func searchJobsHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	skills := r.URL.Query().Get("skills")
	experienceLevel := r.URL.Query().Get("experience")

	// Build filter
	filter := bson.M{}
	if skills != "" {
		skillsList := strings.Split(skills, ",")
		filter["requiredSkills"] = bson.M{"$in": skillsList}
	}
	if experienceLevel != "" {
		filter["experienceLevel"] = experienceLevel
	}

	// Find jobs
	cursor, err := jobsCollection.Find(context.TODO(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var jobs []Job
	if err = cursor.All(context.TODO(), &jobs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jobs)
}

type LeetCodeGraphQLQuery struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

func fetchLeetCodeProfile(username string) (*LeetCodeProfile, error) {
	// GraphQL endpoint for LeetCode
	url := "https://leetcode.com/graphql"

	// Construct GraphQL query
	query := `
	query getUserProfile($username: String!) {
		matchedUser(username: $username) {
			username
			profile {
				ranking
				reputation
				contributionPoints
				userAvatar
			}
			submitStatsGlobal {
				acSubmissionNum {
					difficulty
					count
				}
			}
			problemSolved {
				easySolved
				mediumSolved
				hardSolved
				totalSolved
			}
		}
	}`

	// Prepare request body
	reqBody, err := json.Marshal(LeetCodeGraphQLQuery{
		Query: query,
		Variables: map[string]interface{}{
			"username": username,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	// Send request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse response
	var result struct {
		Data struct {
			MatchedUser struct {
				Username string `json:"username"`
				Profile struct {
					Ranking            int `json:"ranking"`
					Reputation         int `json:"reputation"`
					ContributionPoints int `json:"contributionPoints"`
				} `json:"profile"`
				SubmitStatsGlobal struct {
					AcSubmissionNum []struct {
						Difficulty string `json:"difficulty"`
						Count      int    `json:"count"`
					} `json:"acSubmissionNum"`
				} `json:"submitStatsGlobal"`
				ProblemSolved struct {
					EasySolved   int `json:"easySolved"`
					MediumSolved int `json:"mediumSolved"`
					HardSolved   int `json:"hardSolved"`
					TotalSolved  int `json:"totalSolved"`
				} `json:"problemSolved"`
			} `json:"matchedUser"`
		} `json:"data"`
	}

	// Unmarshal the response
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// Check if user exists
	if result.Data.MatchedUser.Username == "" {
		return nil, fmt.Errorf("user not found")
	}

	// Calculate acceptance rate (this is a mock calculation)
	var acceptanceRate float64
	for _, submission := range result.Data.MatchedUser.SubmitStatsGlobal.AcSubmissionNum {
		if submission.Difficulty == "All" {
			// Mock calculation - in a real scenario, you'd get this from LeetCode API
			acceptanceRate = float64(result.Data.MatchedUser.ProblemSolved.TotalSolved) / 3000 * 100 // Assuming 3000 total problems
			break
		}
	}

	// Create LeetCode profile
	leetCodeProfile := &LeetCodeProfile{
		Username:         result.Data.MatchedUser.Username,
		Ranking:          result.Data.MatchedUser.Profile.Ranking,
		TotalSolved:      result.Data.MatchedUser.ProblemSolved.TotalSolved,
		EasySolved:       result.Data.MatchedUser.ProblemSolved.EasySolved,
		MediumSolved:     result.Data.MatchedUser.ProblemSolved.MediumSolved,
		HardSolved:       result.Data.MatchedUser.ProblemSolved.HardSolved,
		AcceptanceRate:   acceptanceRate,
		ContributionRank: result.Data.MatchedUser.Profile.ContributionPoints,
		Reputation:       result.Data.MatchedUser.Profile.Reputation,
		CreatedAt:        time.Now(),
	}

	return leetCodeProfile, nil
}

func getLeetCodeProfileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Fetch LeetCode profile
	profile, err := fetchLeetCodeProfile(username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching LeetCode profile: %v", err), http.StatusInternalServerError)
		return
	}

	// Save profile to database (optional)
	_, err = profilesCollection.UpdateOne(
		context.TODO(), 
		bson.M{"username": username, "type": "leetcode_profile"},
		bson.M{"$set": profile},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		log.Printf("Failed to save LeetCode profile: %v", err)
		// Non-critical error, continue with response
	}

	// Respond with profile
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(profile)
}

func updateWorkStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure only POST requests are accepted
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode the work status from request body
	var workStatus WorkStatus
	err := json.NewDecoder(r.Body).Decode(&workStatus)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if workStatus.Email == "" || workStatus.CurrentStatus == "" {
		http.Error(w, "Email and current status are required", http.StatusBadRequest)
		return
	}

	// Get user from token or session (simplified for this example)
	email := r.Header.Get("Authorization")
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Set timestamps
	workStatus.Email = strings.TrimPrefix(email, "dummy-token-")
	workStatus.CreatedAt = time.Now()
	workStatus.UpdatedAt = time.Now()

	// Upsert work status (insert or update)
	opts := options.Update().SetUpsert(true)
	filter := bson.M{"email": workStatus.Email}
	update := bson.M{"$set": workStatus}

	_, err = workStatusCollection.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		http.Error(w, "Failed to update work status", http.StatusInternalServerError)
		return
	}

	// Search for matching jobs based on work status
	matchingJobs, err := findMatchingJobs(workStatus)
	if err != nil {
		log.Printf("Error finding matching jobs: %v", err)
		// Non-critical error, continue with response
	}

	// Respond with success and optional matching jobs
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Work status updated successfully",
		"matchingJobs": matchingJobs,
	})
}

func getWorkStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure only GET requests are accepted
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get email from token or session
	email := r.Header.Get("Authorization")
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	email = strings.TrimPrefix(email, "dummy-token-")

	// Find work status
	var workStatus WorkStatus
	err := workStatusCollection.FindOne(context.TODO(), bson.M{"email": email}).Decode(&workStatus)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "No work status found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to retrieve work status", http.StatusInternalServerError)
		return
	}

	// Respond with work status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(workStatus)
}

func findMatchingJobs(workStatus WorkStatus) ([]MatchingJob, error) {
	// Simple job matching algorithm
	var jobs []MatchingJob

	// Find jobs that match skills and experience level
	cursor, err := jobsCollection.Find(context.TODO(), bson.M{
		"requiredSkills": bson.M{"$in": workStatus.Skills},
		"experienceLevel": workStatus.Availability.PreferredRole,
	})
	if err != nil {
		return jobs, err
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var job Job
		if err := cursor.Decode(&job); err == nil {
			jobs = append(jobs, MatchingJob{
				Title:            job.Title,
				Company:          job.Company,
				RequiredSkills:   job.RequiredSkills,
				ExperienceLevel:  job.ExperienceLevel,
			})
		}
	}

	return jobs, nil
}

func main() {
	// Initialize database
	err := initDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Define routes
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/save-seeker-profile", saveSeekerProfileHandler)
	http.HandleFunc("/save-recruiter-profile", saveRecruiterProfileHandler)
	
	// New job-related routes
	http.HandleFunc("/create-job", createJobHandler)
	http.HandleFunc("/search-jobs", searchJobsHandler)
	http.HandleFunc("/get-leetcode-profile", getLeetCodeProfileHandler)
	http.HandleFunc("/update-work-status", updateWorkStatusHandler)
	http.HandleFunc("/get-work-status", getWorkStatusHandler)

	// Start server
	log.Println("Server starting on :8000")
	err = http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
