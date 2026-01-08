package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var db *sql.DB
var adminPassword string
var uploadsDir = "./uploads" // Directory to save files, relative to the binary

// logError inserts an entry into the errors table (reusing from reference)
func logError(errorType, remark string) {
	london, err := time.LoadLocation("Europe/London")
	if err != nil {
		timestamp := time.Now().UTC()
		_, dbErr := db.Exec("INSERT INTO errors (timestamp, error_type, remark) VALUES (?, ?, ?)", timestamp, errorType, fmt.Sprintf("Timezone error: %v; %s", err, remark))
		if dbErr != nil {
			// Silent fail
		}
		return
	}
	timestamp := time.Now().In(london)

	query := `INSERT INTO errors (timestamp, error_type, remark) VALUES (?, ?, ?)`
	_, err = db.Exec(query, timestamp, errorType, remark)
	if err != nil {
		// Silent fail
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		logError("STARTUP_ERROR", fmt.Sprintf("Error loading .env file: %v", err))
		os.Exit(1)
	}

	dbUser := os.Getenv("DB_USERNAME")
	dbPass := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		logError("CONFIG_ERROR", "ADMIN_PASSWORD not defined in .env")
		os.Exit(1)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPass, dbHost, dbPort, dbName)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		logError("DB_CONNECTION_ERROR", fmt.Sprintf("Failed to connect to DB: %v", err))
		os.Exit(1)
	}
	defer db.Close()

	// Create tables if not exist
	createTables()

	// Ensure uploads directory exists
	if err := os.MkdirAll(uploadsDir, 0755); err != nil { // drwxr-xr-x, no exec for others
		logError("STARTUP_ERROR", fmt.Sprintf("Failed to create uploads dir: %v", err))
		os.Exit(1)
	}

	r := mux.NewRouter()

	// Submission handler
	r.HandleFunc("/submit", submitHandler).Methods("POST")

	// Admin interface routes (protected)
	// Admin interface routes (protected)
	adminRouter := r.PathPrefix("/admin").Subrouter()
	adminRouter.Use(basicAuthMiddleware)
	adminRouter.HandleFunc("/", adminHomeHandler).Methods("GET") // Matches /admin/
	adminRouter.HandleFunc("/create-form", createFormHandler).Methods("POST")
	adminRouter.HandleFunc("/forms/{form_id}", viewSubmissionsHandler).Methods("GET")

	// File serving (protected under /admin/files/)
	adminRouter.HandleFunc("/files/{path:.*}", serveFileHandler).Methods("GET")

	// Add this: Explicit handler for /admin (without trailing slash) - redirects to /admin/
	r.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	}).Methods("GET")

	// CORS configuration: Allow only from *.peaceandhumanity.org
	corsHandler := handlers.CORS(
		handlers.AllowedOriginValidator(func(origin string) bool {
			return strings.HasSuffix(origin, ".peaceandhumanity.org") || origin == "https://peaceandhumanity.org"
		}),
		handlers.AllowedMethods([]string{"GET", "POST"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Accept"}),
	)

	http.Handle("/", corsHandler(r))

	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	if certFile == "" || keyFile == "" {
		logError("CONFIG_ERROR", "CERT_FILE or KEY_FILE not defined in .env")
		os.Exit(1)
	}

	err = http.ListenAndServeTLS(":5003", certFile, keyFile, nil)
	if err != nil {
		logError("SERVER_ERROR", fmt.Sprintf("Server failed: %v", err))
		os.Exit(1)
	}
}

// createTables sets up the necessary database tables
func createTables() {
	// Forms table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS forms (
			form_id INT AUTO_INCREMENT PRIMARY KEY,
			form_name VARCHAR(255) NOT NULL
		)
	`)
	if err != nil {
		logError("DB_SETUP_ERROR", fmt.Sprintf("Failed to create forms table: %v", err))
	}

	// Submissions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS submissions (
			submission_id INT AUTO_INCREMENT PRIMARY KEY,
			form_id INT NOT NULL,
			data JSON NOT NULL,
			files JSON,  -- Array of file paths
			timestamp DATETIME NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			FOREIGN KEY (form_id) REFERENCES forms(form_id)
		)
	`)
	if err != nil {
		logError("DB_SETUP_ERROR", fmt.Sprintf("Failed to create submissions table: %v", err))
	}
}

// submitHandler handles form submissions
func submitHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max
		logError("SUBMIT_PARSE_ERROR", fmt.Sprintf("Failed to parse form: %v", err))
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	formIDStr := r.FormValue("form_id")
	if formIDStr == "" {
		logError("SUBMIT_NO_FORM_ID", "No form_id provided")
		http.Error(w, "form_id is required", http.StatusBadRequest)
		return
	}

	formID, err := strconv.Atoi(formIDStr)
	if err != nil || formID <= 0 {
		logError("SUBMIT_INVALID_FORM_ID", fmt.Sprintf("Invalid form_id: %s", formIDStr))
		http.Error(w, "Invalid form_id", http.StatusBadRequest)
		return
	}

	// Check if form exists
	var exists int
	err = db.QueryRow("SELECT COUNT(*) FROM forms WHERE form_id = ?", formID).Scan(&exists)
	if err != nil || exists == 0 {
		logError("SUBMIT_FORM_NOT_FOUND", fmt.Sprintf("Form not found for id: %d", formID))
		http.Error(w, "Form not found", http.StatusNotFound)
		return
	}

	// Collect form data (excluding files and form_id)
	data := make(map[string]interface{})
	for key, values := range r.Form {
		if key != "form_id" && len(values) > 0 {
			data[key] = values[0] // Take first value for simplicity
		}
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		logError("SUBMIT_JSON_ERROR", fmt.Sprintf("Failed to marshal data: %v", err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Handle files
	var filePaths []string
	submissionDir := filepath.Join(uploadsDir, fmt.Sprintf("form_%d", formID), fmt.Sprintf("submission_%d", time.Now().UnixNano())) // Unique dir per submission
	if err := os.MkdirAll(submissionDir, 0755); err != nil {
		logError("SUBMIT_MKDIR_ERROR", fmt.Sprintf("Failed to create submission dir: %v", err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	for _, fileHeaders := range r.MultipartForm.File {
		for _, fileHeader := range fileHeaders {
			file, err := fileHeader.Open()
			if err != nil {
				logError("SUBMIT_FILE_OPEN_ERROR", fmt.Sprintf("Failed to open file: %v", err))
				continue
			}
			defer file.Close()

			// Sanitize filename
			filename := strings.ReplaceAll(fileHeader.Filename, "..", "") // Prevent path traversal
			filename = strings.ReplaceAll(filename, "/", "")              // No subdirs
			dstPath := filepath.Join(submissionDir, filename)

			dst, err := os.Create(dstPath)
			if err != nil {
				logError("SUBMIT_FILE_CREATE_ERROR", fmt.Sprintf("Failed to create file: %v", err))
				continue
			}
			defer dst.Close()

			if _, err := io.Copy(dst, file); err != nil {
				logError("SUBMIT_FILE_COPY_ERROR", fmt.Sprintf("Failed to copy file: %v", err))
				continue
			}

			// Set permissions: rw-r--r-- (no exec)
			if err := os.Chmod(dstPath, 0644); err != nil {
				logError("SUBMIT_CHMOD_ERROR", fmt.Sprintf("Failed to set file perms: %v", err))
			}

			filePaths = append(filePaths, dstPath)
		}
	}

	filesJSON, _ := json.Marshal(filePaths) // Ignore err, empty if no files

	// Insert submission
	timestamp := time.Now()
	ip := r.RemoteAddr
	_, err = db.Exec(`
		INSERT INTO submissions (form_id, data, files, timestamp, ip_address)
		VALUES (?, ?, ?, ?, ?)
	`, formID, dataJSON, filesJSON, timestamp, ip)
	if err != nil {
		logError("SUBMIT_DB_INSERT_ERROR", fmt.Sprintf("Failed to insert submission: %v", err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	logError("SUBMIT_SUCCESS", fmt.Sprintf("Submission for form %d from IP %s", formID, ip))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Submission received"))
}

// basicAuthMiddleware protects admin routes with password
func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || pass != adminPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminHomeHandler shows list of forms and create form option
func adminHomeHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT form_id, form_name FROM forms ORDER BY form_id ASC")
	if err != nil {
		logError("ADMIN_DB_ERROR", fmt.Sprintf("Failed to query forms: %v", err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var formsHTML strings.Builder
	formsHTML.WriteString("<ul>")
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		formsHTML.WriteString(fmt.Sprintf(`<li><a href="/admin/forms/%d">%d: %s</a></li>`, id, id, html.EscapeString(name)))
	}
	formsHTML.WriteString("</ul>")

	htmlResponse := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head><title>Admin Interface</title></head>
		<body>
			<h1>Forms</h1>
			%s
			<h2>Create New Form</h2>
			<form action="/admin/create-form" method="POST">
				<label>Form Name:</label><input type="text" name="form_name" required><br>
				<button type="submit">Create</button>
			</form>
		</body>
		</html>
	`, formsHTML.String())

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlResponse))
}

// createFormHandler creates a new form
func createFormHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	formName := r.FormValue("form_name")
	if formName == "" {
		http.Error(w, "form_name required", http.StatusBadRequest)
		return
	}

	res, err := db.Exec("INSERT INTO forms (form_name) VALUES (?)", formName)
	if err != nil {
		logError("ADMIN_CREATE_FORM_ERROR", fmt.Sprintf("Failed to create form: %v", err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	id, _ := res.LastInsertId()
	logError("ADMIN_CREATE_SUCCESS", fmt.Sprintf("Created form %d: %s", id, formName))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// viewSubmissionsHandler shows submissions for a form
func viewSubmissionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formIDStr := vars["form_id"]
	formID, err := strconv.Atoi(formIDStr)
	if err != nil {
		http.Error(w, "Invalid form_id", http.StatusBadRequest)
		return
	}

	var formName string
	db.QueryRow("SELECT form_name FROM forms WHERE form_id = ?", formID).Scan(&formName)

	rows, err := db.Query(`
		SELECT submission_id, data, files, timestamp, ip_address
		FROM submissions 
		WHERE form_id = ? 
		ORDER BY submission_id DESC
	`, formID)
	if err != nil {
		logError("ADMIN_DB_ERROR", fmt.Sprintf("Query failed: %v", err))
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subsHTML strings.Builder
	subsHTML.WriteString(fmt.Sprintf("<h1>Submissions for Form %d: %s</h1><hr>", formID, html.EscapeString(formName)))

	submissionCount := 0

	for rows.Next() {
		submissionCount++

		var subID int
		var dataJSON []byte
		var filesJSON sql.NullString
		var timestamp time.Time
		var ip string

		if err := rows.Scan(&subID, &dataJSON, &filesJSON, &timestamp, &ip); err != nil {
			subsHTML.WriteString(fmt.Sprintf("<p>Error reading row: %v</p>", err))
			continue
		}

		// Try to parse data JSON - if fails, show raw
		var data map[string]interface{}
		dataStr := "<em>Invalid/malformed form data (raw below):</em><br><pre>" + html.EscapeString(string(dataJSON)) + "</pre>"
		if json.Unmarshal(dataJSON, &data) == nil {
			dataStr = ""
			for key, value := range data {
				valStr := fmt.Sprintf("%v", value)
				dataStr += fmt.Sprintf("<strong>%s:</strong> %s<br>", html.EscapeString(key), html.EscapeString(valStr))
			}
		}

		// Files
		var files []string
		if filesJSON.Valid {
			json.Unmarshal([]byte(filesJSON.String), &files)
		}

		filesStr := "<em>No files</em>"
		if len(files) > 0 {
			filesStr = ""
			for _, f := range files {
				relPath, _ := filepath.Rel(uploadsDir, f)
				base := filepath.Base(f)
				filesStr += fmt.Sprintf(`<a href="/admin/files/%s" download>📎 %s</a><br>`, html.EscapeString(relPath), html.EscapeString(base))
			}
		}

		ts := timestamp.Format("2006-01-02 15:04:05")
		if timestamp.IsZero() {
			ts = "Not recorded"
		}

		subsHTML.WriteString(fmt.Sprintf(`
			<div style="background:#fff;padding:20px;margin:20px 0;border:1px solid #ddd;border-radius:8px;">
				<h3>Submission #%d</h3>
				<p><strong>Time:</strong> %s<br><strong>IP:</strong> %s</p>
				<h4>Data:</h4>
				<div style="margin-left:20px;">%s</div>
				<h4>Files:</h4>
				<div style="margin-left:20px;">%s</div>
			</div>
		`, subID, ts, html.EscapeString(ip), dataStr, filesStr))
	}

	if submissionCount == 0 {
		subsHTML.WriteString("<p><em>No submissions found.</em></p>")
	}

	subsHTML.WriteString(`<p><a href="/admin/">← Back to Forms List</a></p>`)

	fullHTML := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Submissions</title></head><body style="font-family:Arial;background:#f9f9f9;padding:20px;">%s</body></html>`, subsHTML.String())

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fullHTML))
}

// serveFileHandler serves files from uploads dir (protected)
func serveFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	relPath := vars["path"]
	fullPath := filepath.Join(uploadsDir, relPath)

	// Prevent path traversal
	if !strings.HasPrefix(fullPath, uploadsDir) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	file, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not found", http.StatusNotFound)
		} else {
			logError("FILE_SERVE_ERROR", fmt.Sprintf("Failed to open file: %v", err))
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.ServeContent(w, r, filepath.Base(fullPath), stat.ModTime(), file)
}
