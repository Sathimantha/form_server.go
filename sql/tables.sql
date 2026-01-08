CREATE TABLE IF NOT EXISTS forms (
    form_id INT AUTO_INCREMENT PRIMARY KEY,
    form_name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
    submission_id INT AUTO_INCREMENT PRIMARY KEY,
    form_id INT NOT NULL,
    data JSON NOT NULL,
    files JSON DEFAULT NULL,  -- Will store array of file paths, NULL if no files
    timestamp DATETIME NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    FOREIGN KEY (form_id) REFERENCES forms(form_id) ON DELETE CASCADE
);