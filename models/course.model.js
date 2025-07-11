// models/Courses.js
import pool from '../db/index.js'

class Courses {
  // Create a new course
  static async create(courseData) {
    const { 
      course_code, 
      course_name, 
      instructor_name, 
      instructor_id, 
      avail, 
      defor, 
      isornot, 
      slot, 
      credit, 
      ltpc 
    } = courseData;
    
    const query = `
      INSERT INTO courses (course_code, course_name, instructor_name, instructor_id, avail, defor, isornot, slot, credit, ltpc)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [
        course_code, course_name, instructor_name, instructor_id, 
        avail, defor, isornot, slot, credit, ltpc
      ]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating course: ${error.message}`);
    }
  }

  // Find course by course code
  static async findByCode(course_code) {
    const query = 'SELECT * FROM courses WHERE course_code = $1';
    
    try {
      const result = await pool.query(query, [course_code]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding course by code: ${error.message}`);
    }
  }

  // Find courses by instructor
  static async findByInstructor(instructor_id) {
    const query = 'SELECT * FROM courses WHERE instructor_id = $1';
    
    try {
      const result = await pool.query(query, [instructor_id]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding courses by instructor: ${error.message}`);
    }
  }

  // Find available courses
  static async findAvailable() {
    const query = 'SELECT * FROM courses WHERE avail = true';
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding available courses: ${error.message}`);
    }
  }

  // Find courses by slot
  static async findBySlot(slot) {
    const query = 'SELECT * FROM courses WHERE slot = $1';
    
    try {
      const result = await pool.query(query, [slot]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding courses by slot: ${error.message}`);
    }
  }

  // Get all courses
  static async findAll() {
    const query = 'SELECT * FROM courses ORDER BY course_code';
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error fetching all courses: ${error.message}`);
    }
  }

  // Update course
  static async update(course_code, updateData) {
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

    values.push(course_code);
    const query = `
      UPDATE courses 
      SET ${fields.join(', ')} 
      WHERE course_code = $${paramCount}
      RETURNING *
    `;

    try {
      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating course: ${error.message}`);
    }
  }

  // Delete course
  static async delete(course_code) {
    const query = 'DELETE FROM courses WHERE course_code = $1 RETURNING *';
    
    try {
      const result = await pool.query(query, [course_code]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting course: ${error.message}`);
    }
  }

  // Get course statistics
  static async getStats() {
    const query = `
      SELECT 
        COUNT(*) as total_courses,
        COUNT(CASE WHEN avail = true THEN 1 END) as available_courses,
        COUNT(DISTINCT instructor_id) as total_instructors,
        AVG(credit) as avg_credits
      FROM courses
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting course statistics: ${error.message}`);
    }
  }
}

module.export = Courses;