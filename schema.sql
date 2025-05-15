-- Drop tables if they exist
DROP TABLE IF EXISTS voters;
DROP TABLE IF EXISTS candidates;
DROP TABLE IF EXISTS votes;
DROP TABLE IF EXISTS admin;

-- Create voters table
CREATE TABLE voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    class TEXT,
    section TEXT,
    roll_no TEXT,
    subject TEXT,  -- For teachers
    voting_code TEXT NOT NULL UNIQUE,
    is_teacher INTEGER NOT NULL DEFAULT 0,
    has_voted INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create candidates table
CREATE TABLE candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    gender TEXT NOT NULL CHECK (gender IN ('Male', 'Female')),
    image_path TEXT,
    logo_path TEXT,
    slogan TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create votes table
CREATE TABLE votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (voter_id) REFERENCES voters (id),
    FOREIGN KEY (candidate_id) REFERENCES candidates (id)
);

-- Create admin table
CREATE TABLE admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user (username: admin, password: admin)
INSERT INTO admin (username, password_hash) 
VALUES ('admin', '$2b$12$qKU3YP7Nz3kzWkxpYKiMqe4JfN9aKC7GW4q1Eb1iiL6TgW/LQTKCm');

-- Create a view for weighted votes (teachers count as 6 points)
CREATE VIEW vote_weights AS
SELECT
    v.id,
    v.voter_id,
    v.candidate_id,
    v.timestamp,
    CASE WHEN vr.is_teacher = 1 THEN 6 ELSE 1 END as vote_weight
FROM votes v
JOIN voters vr ON v.voter_id = vr.id;

CREATE INDEX idx_voters_is_teacher ON voters(is_teacher);
CREATE INDEX idx_voters_has_voted ON voters(has_voted);
CREATE INDEX idx_voters_class_section ON voters(class, section);
CREATE INDEX idx_voters_voting_code ON voters(voting_code);
CREATE INDEX idx_votes_candidate_id ON votes(candidate_id);
CREATE INDEX idx_votes_voter_id ON votes(voter_id);
CREATE INDEX idx_candidates_gender ON candidates(gender); 