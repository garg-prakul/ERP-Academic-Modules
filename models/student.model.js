// models/Students.js
import pool from '../db/index.js'

class Students {
  // Create a new student
  static async create(studentData) {
    const { 
      email, 
      password, 
      roll_no, 
      student_branch_code, 
      student_name, 
      submission_count, 
      registration_count 
    } = studentData;
    
    const query = `
      INSERT INTO students (email, password, roll_no, student_branch_code, student_name, submission_count, registration_count)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [
        email, password, roll_no, student_branch_code, 
        student_name, submission_count || 0, registration_count || 0
      ]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating student: ${error.message}`);
    }
  }

  // Find student by email
  static async findByEmail(email) {
    const query = 'SELECT * FROM students WHERE email = $1';
    
    try {
      const result = await pool.query(query, [email]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding student by email: ${error.message}`);
    }
  }

  // Find student by roll number
  static async findByRollNo(roll_no) {
    const query = 'SELECT * FROM students WHERE roll_no = $1';
    
    try {
      const result = await pool.query(query, [roll_no]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding student by roll number: ${error.message}`);
    }
  }

  // Find students by branch
  static async findByBranch(student_branch_code) {
    const query = 'SELECT * FROM students WHERE student_branch_code = $1';
    
    try {
      const result = await pool.query(query, [student_branch_code]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding students by branch: ${error.message}`);
    }
  }

  // Get all students
  static async findAll() {
    const query = 'SELECT email, roll_no, student_branch_code, student_name, submission_count, registration_count FROM students ORDER BY roll_no';
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error fetching all students: ${error.message}`);
    }
  }

  // Update student
  static async update(email, updateData) {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(updateData)) {
      if (value !== undefined) {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    }

    if (fields.length === 0) {
      throw new Error('No fields to update');
    }

    values.push(email);
    const query = `
      UPDATE students 
      SET ${fields.join(', ')} 
      WHERE email = $${paramCount}
      RETURNING *
    `;

    try {
      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating student: ${error.message}`);
    }
  }

  // Increment submission count
  static async incrementSubmissionCount(email) {
    const query = `
      UPDATE students 
      SET submission_count = submission_count + 1 
      WHERE email = $1 
      RETURNING submission_count
    `;
    
    try {
      const result = await pool.query(query, [email]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error incrementing submission count: ${error.message}`);
    }
  }

  // Increment registration count
  static async incrementRegistrationCount(email) {
    const query = `
      UPDATE students 
      SET registration_count = registration_count + 1 
      WHERE email = $1 
      RETURNING registration_count
    `;
    
    try {
      const result = await pool.query(query, [email]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error incrementing registration count: ${error.message}`);
    }
  }

  // Delete student
  static async delete(email) {
    const query = 'DELETE FROM students WHERE email = $1 RETURNING *';
    
    try {
      const result = await pool.query(query, [email]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting student: ${error.message}`);
    }
  }

  // Get student statistics
  static async getStats() {
    const query = `
      SELECT 
        COUNT(*) as total_students,
        COUNT(DISTINCT student_branch_code) as total_branches,
        AVG(submission_count) as avg_submissions,
        AVG(registration_count) as avg_registrations
      FROM students
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting student statistics: ${error.message}`);
    }
  }
}

module.export = Students;