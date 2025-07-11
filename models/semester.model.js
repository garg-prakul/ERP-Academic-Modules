import pool from '../db/index.js'

class Semester {
  static async create(semesterData) {
    const { semester_id, roll_no, semester_number, year } = semesterData;
    
    const query = `
      INSERT INTO semester (semester_id, roll_no, semester_number, year)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [semester_id, roll_no, semester_number, year]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating semester: ${error.message}`);
    }
  }

  static async findByRollNo(roll_no) {
    const query = 'SELECT * FROM semester WHERE roll_no = $1 ORDER BY year DESC, semester_number DESC';
    
    try {
      const result = await pool.query(query, [roll_no]);
      return result.rows;
    } catch (error) {
      throw new Error(`Error finding semesters by roll number: ${error.message}`);
    }
  }

  static async findById(semester_id) {
    const query = 'SELECT * FROM semester WHERE semester_id = $1';
    
    try {
      const result = await pool.query(query, [semester_id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding semester by ID: ${error.message}`);
    }
  }

  static async getCurrentSemester(roll_no) {
    const query = `
      SELECT * FROM semester 
      WHERE roll_no = $1 
      ORDER BY year DESC, semester_number DESC 
      LIMIT 1
    `;
    
    try {
      const result = await pool.query(query, [roll_no]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting current semester: ${error.message}`);
    }
  }

  static async update(semester_id, updateData) {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(updateData)) {
      if (value !== undefined) {
        fields.push(`${key} = ${paramCount}`);
        values.push(value);
        paramCount++;
      }
    }

    if (fields.length === 0) {
      throw new Error('No fields to update');
    }

    values.push(semester_id);
    const query = `
      UPDATE semester 
      SET ${fields.join(', ')} 
      WHERE semester_id = ${paramCount}
      RETURNING *
    `;

    try {
      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating semester: ${error.message}`);
    }
  }
}


module.export = Semester; 