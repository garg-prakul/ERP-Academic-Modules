import pool from '../db/index.js'

class Enrollment {
  static async create(enrollmentData) {
    const { enrollment_id, roll_no, course_code, semester_id, grade } = enrollmentData;
    
    const query = `
      INSERT INTO enrollment (enrollment_id, roll_no, course_code, semester_id, grade)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [enrollment_id, roll_no, course_code, semester_id, grade]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating enrollment: ${error.message}`);
    }
  }

  static async findByRollNo(roll_no) {
    const query = `
      SELECT 
        e.*,
        c.course_name,
        c.instructor_name,
        c.credit,
        s.semester_number,
        s.year
      FROM enrollment e
      JOIN courses c ON e.course_code = c.course_code
      JOIN semester s ON e.semester_id = s.semester_id
      WHERE e.roll_no = $1
      ORDER BY s.year DESC, s.semester_number DESC
    `;
    
    try {
      const result = await pool.query(query, [roll_no]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding enrollments by roll number: ${error.message}`);
    }
  }

  static async findByCourseCode(course_code) {
    const query = `
      SELECT 
        e.*,
        s.student_name,
        s.student_branch_code,
        sem.semester_number,
        sem.year
      FROM enrollment e
      JOIN students s ON e.roll_no = s.roll_no
      JOIN semester sem ON e.semester_id = sem.semester_id
      WHERE e.course_code = $1
      ORDER BY sem.year DESC, sem.semester_number DESC
    `;
    
    try {
      const result = await pool.query(query, [course_code]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding enrollments by course code: ${error.message}`);
    }
  }

  static async updateGrade(enrollment_id, grade) {
    const query = `
      UPDATE enrollment 
      SET grade = $1 
      WHERE enrollment_id = $2
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [grade, enrollment_id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating grade: ${error.message}`);
    }
  }

  static async getStudentGrades(roll_no, semester_id) {
    const query = `
      SELECT 
        e.*,
        c.course_name,
        c.credit
      FROM enrollment e
      JOIN courses c ON e.course_code = c.course_code
      WHERE e.roll_no = $1 AND e.semester_id = $2
    `;
    
    try {
      const result = await pool.query(query, [roll_no, semester_id]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error getting student grades: ${error.message}`);
    }
  }

  static async getStats() {
    const query = `
      SELECT 
        COUNT(*) as total_enrollments,
        COUNT(DISTINCT roll_no) as unique_students,
        COUNT(DISTINCT course_code) as unique_courses,
        COUNT(CASE WHEN grade IS NOT NULL THEN 1 END) as graded_enrollments
      FROM enrollment
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting enrollment statistics: ${error.message}`);
    }
  }
}

module.export = Enrollment;