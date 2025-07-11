// models/Instructors.js
import pool from '../db/index.js'

class Instructors {
  // Create a new instructor
  static async create(instructorData) {
    const { email, password, instructor_id, instructor_name } = instructorData;
    
    const query = `
      INSERT INTO instructors (email, password, instructor_id, instructor_name)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [email, password, instructor_id, instructor_name]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating instructor: ${error.message}`);
    }
  }

  // Find instructor by email
  static async findByEmail(email) {
    const query = 'SELECT * FROM instructors WHERE email = $1';
    
    try {
      const result = await pool.query(query, [email]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding instructor by email: ${error.message}`);
    }
  }

  // Find instructor by ID
  static async findById(instructor_id) {
    const query = 'SELECT * FROM instructors WHERE instructor_id = $1';
    
    try {
      const result = await pool.query(query, [instructor_id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding instructor by ID: ${error.message}`);
    }
  }

  // Get all instructors
  static async findAll() {
    const query = 'SELECT email, instructor_id, instructor_name FROM instructors ORDER BY instructor_name';
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error fetching all instructors: ${error.message}`);
    }
  }

  // Update instructor
  static async update(instructor_id, updateData) {
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

    values.push(instructor_id);
    const query = `
      UPDATE instructors 
      SET ${fields.join(', ')} 
      WHERE instructor_id = $${paramCount}
      RETURNING *
    `;

    try {
      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating instructor: ${error.message}`);
    }
  }

  // Delete instructor
  static async delete(instructor_id) {
    const query = 'DELETE FROM instructors WHERE instructor_id = $1 RETURNING *';
    
    try {
      const result = await pool.query(query, [instructor_id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting instructor: ${error.message}`);
    }
  }

  // Get instructor with their courses
  static async getWithCourses(instructor_id) {
    const query = `
      SELECT 
        i.instructor_id,
        i.instructor_name,
        i.email,
        c.course_code,
        c.course_name,
        c.slot,
        c.credit
      FROM instructors i
      LEFT JOIN courses c ON i.instructor_id = c.instructor_id
      WHERE i.instructor_id = $1
    `;
    
    try {
      const result = await pool.query(query, [instructor_id]);
      
      if (result.rows.length === 0) {
        return null;
      }

      const instructor = {
        instructor_id: result.rows[0].instructor_id,
        instructor_name: result.rows[0].instructor_name,
        email: result.rows[0].email,
        courses: []
      };

      result.rows.forEach(row => {
        if (row.course_code) {
          instructor.courses.push({
            course_code: row.course_code,
            course_name: row.course_name,
            slot: row.slot,
            credit: row.credit
          });
        }
      });

      return instructor;
    } catch (error) {
      throw new Error(`Error getting instructor with courses: ${error.message}`);
    }
  }

  // Get instructor statistics
  static async getStats() {
    const query = `
      SELECT 
        COUNT(*) as total_instructors,
        COUNT(DISTINCT c.instructor_id) as active_instructors,
        COUNT(c.course_code) as total_courses_taught
      FROM instructors i
      LEFT JOIN courses c ON i.instructor_id = c.instructor_id
    `;
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting instructor statistics: ${error.message}`);
    }
  }
}

module.export = Instructors;