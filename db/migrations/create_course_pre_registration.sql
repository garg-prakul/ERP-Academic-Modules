-- Add if not exists
ALTER TABLE course_pre_registration 
ADD CONSTRAINT unique_student_course_prereg 
UNIQUE (roll_no, course_code);

-- Add created_at column if not exists
ALTER TABLE course_pre_registration 
ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
