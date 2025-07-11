import pool from '../db/index.js'

class Registration {
  static async create(regData) {
    const { roll_no, course_code, slot } = regData;
    
    const query = `
      INSERT INTO course_registration (roll_no, course_code, slot)
      VALUES ($1, $2, $3)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [roll_no, course_code, slot]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating registration: ${error.message}`);
    }
  }

  static async findByRollNo(roll_no) {
    const query = `
      SELECT 
        cr.*,
        c.course_name,
        c.instructor_name,
        c.credit
      FROM course_registration cr
      JOIN courses c ON cr.course_code = c.course_code
      WHERE cr.roll_no = $1
    `;
    
    try {
      const result = await pool.query(query, [roll_no]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding registrations by roll number: ${error.message}`);
    }
  }

  static async findByCourseCode(course_code) {
    const query = `
      SELECT 
        cr.*,
        s.student_name,
        s.student_branch_code
      FROM course_registration cr
      JOIN students s ON cr.roll_no = s.roll_no
      WHERE cr.course_code = $1
    `;
    
    try {
      const result = await pool.query(query, [course_code]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding registrations by course code: ${error.message}`);
    }
  }

  static async checkDuplicate(roll_no, course_code) {
    const query = `
      SELECT * FROM course_registration 
      WHERE roll_no = $1 AND course_code = $2
    `;
    
    try {
      const result = await pool.query(query, [roll_no, course_code]);
      return result.rows.length > 0;
    } catch (error) {
      throw new Error(`Error checking duplicate registration: ${error.message}`);
    }
  }

  static async delete(roll_no, course_code) {
    const query = 'DELETE FROM course_registration WHERE roll_no = $1 AND course_code = $2 RETURNING *';
    
    try {
      const result = await pool.query(query, [roll_no, course_code]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting registration: ${error.message}`);
    }
  }

  static async getStats() {
    const query = `
      SELECT 
        COUNT(*) as total_registrations,
        COUNT(DISTINCT roll_no) as unique_students,
        COUNT(DISTINCT course_code) as unique_courses
      FROM course_registration
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting registration statistics: ${error.message}`);
    }
  }
}


module.export = Registration;