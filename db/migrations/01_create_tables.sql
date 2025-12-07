CREATE TABLE IF NOT EXISTS course_pre_registration (
    id SERIAL PRIMARY KEY,
    roll_no VARCHAR(10) NOT NULL,
    course_code VARCHAR(10) NOT NULL,
    status VARCHAR(10) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_student_course_prereg UNIQUE (roll_no, course_code),
    FOREIGN KEY (roll_no) REFERENCES students(roll_no),
    FOREIGN KEY (course_code) REFERENCES courses(course_code)
);

-- Add submission_count to students if not exists
ALTER TABLE students 
ADD COLUMN IF NOT EXISTS submission_count INTEGER DEFAULT 0;
