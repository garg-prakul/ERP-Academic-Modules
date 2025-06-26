-- Add unique constraint to prevent duplicate pre-registrations
ALTER TABLE course_pre_registration 
ADD CONSTRAINT unique_student_course_registration 
UNIQUE (roll_no, course_code);
