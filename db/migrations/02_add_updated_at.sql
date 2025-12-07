-- Verify table structure
SELECT * FROM course_pre_registration LIMIT 0;

-- Add updated_at column if not exists and verify other columns
DO $$ 
BEGIN
    -- Add updated_at if it doesn't exist
    IF NOT EXISTS (SELECT 1 
                  FROM information_schema.columns 
                  WHERE table_name='course_pre_registration' 
                  AND column_name='updated_at') THEN
        ALTER TABLE course_pre_registration 
        ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;

    -- Verify all required columns exist
    IF NOT EXISTS (SELECT 1 
                  FROM information_schema.columns 
                  WHERE table_name='course_pre_registration' 
                  AND column_name IN ('id', 'roll_no', 'course_code', 'status', 'created_at', 'slot')) THEN
        RAISE EXCEPTION 'Missing required columns in course_pre_registration table';
    END IF;
END $$;

-- Create or replace the trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Drop trigger if exists and create new one
DROP TRIGGER IF EXISTS update_course_pre_registration_updated_at ON course_pre_registration;

CREATE TRIGGER update_course_pre_registration_updated_at
    BEFORE UPDATE ON course_pre_registration
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
