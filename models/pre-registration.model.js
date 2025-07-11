// models/PreRegistration.js
import pool from '../db/index.js'

class PreRegistration {
  // Create a new pre-registration
  static async create(preRegData) {
    const { roll_no, course_code, slot, status, created_at } = preRegData;
    
    const query = `
      INSERT INTO course_pre_registration (roll_no, course_code, slot, status, created_at)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [
        roll_no, course_code, slot, status || 'pending', created_at || new Date()
      ]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating pre-registration: ${error.message}`);
    }
  }

  // Find pre-registration by ID
  static async findById(id) {
    const query = 'SELECT * FROM course_pre_registration WHERE id = $1';
    
    try {
      const result = await pool.query(query, [id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding pre-registration by ID: ${error.message}`);
    }
  }

  // Find pre-registrations by student roll number
  static async findByRollNo(roll_no) {
    const query = `
      SELECT 
        cpr.*,
        c.course_name,
        c.instructor_name,
        c.credit
      FROM course_pre_registration cpr
      JOIN courses c ON cpr.course_code = c.course_code
      WHERE cpr.roll_no = $1
      ORDER BY cpr.created_at DESC
    `;
    
    try {
      const result = await pool.query(query, [roll_no]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding pre-registrations by roll number: ${error.message}`);
    }
  }

  // Find pre-registrations by course code
  static async findByCourseCode(course_code) {
    const query = `
      SELECT 
        cpr.*,
        s.student_name,
        s.student_branch_code
      FROM course_pre_registration cpr
      JOIN students s ON cpr.roll_no = s.roll_no
      WHERE cpr.course_code = $1
      ORDER BY cpr.created_at DESC
    `;
    
    try {
      const result = await pool.query(query, [course_code]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding pre-registrations by course code: ${error.message}`);
    }
  }

  // Find pre-registrations by status
  static async findByStatus(status) {
    const query = `
      SELECT 
        cpr.*,
        c.course_name,
        c.instructor_name,
        s.student_name,
        s.student_branch_code
      FROM course_pre_registration cpr
      JOIN courses c ON cpr.course_code = c.course_code
      JOIN students s ON cpr.roll_no = s.roll_no
      WHERE cpr.status = $1
      ORDER BY cpr.created_at DESC
    `;
    
    try {
      const result = await pool.query(query, [status]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding pre-registrations by status: ${error.message}`);
    }
  }

  // Check if student has already pre-registered for a course
  static async checkDuplicate(roll_no, course_code) {
    const query = `
      SELECT * FROM course_pre_registration 
      WHERE roll_no = $1 AND course_code = $2
    `;
    
    try {
      const result = await pool.query(query, [roll_no, course_code]);
      return result.rows.length > 0;
    } catch (error) {
      throw new Error(`Error checking duplicate pre-registration: ${error.message}`);
    }
  }

  // Update pre-registration status
  static async updateStatus(id, status) {
    const query = `
      UPDATE course_pre_registration 
      SET status = $1 
      WHERE id = $2
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [status, id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating pre-registration status: ${error.message}`);
    }
  }

  // Delete pre-registration
  static async delete(id) {
    const query = 'DELETE FROM course_pre_registration WHERE id = $1 RETURNING *';
    
    try {
      const result = await pool.query(query, [id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting pre-registration: ${error.message}`);
    }
  }

  // Get all pre-registrations
  static async findAll() {
    const query = `
      SELECT 
        cpr.*,
        c.course_name,
        c.instructor_name,
        s.student_name,
        s.student_branch_code
      FROM course_pre_registration cpr
      JOIN courses c ON cpr.course_code = c.course_code
      JOIN students s ON cpr.roll_no = s.roll_no
      ORDER BY cpr.created_at DESC
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error fetching all pre-registrations: ${error.message}`);
    }
  }

  // Get pre-registration statistics
  static async getStats() {
    const query = `
      SELECT 
        COUNT(*) as total_preregistrations,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_count,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_count,
        COUNT(DISTINCT roll_no) as unique_students,
        COUNT(DISTINCT course_code) as unique_courses
      FROM course_pre_registration
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting pre-registration statistics: ${error.message}`);
    }
  }
}

module.export = PreRegistration;