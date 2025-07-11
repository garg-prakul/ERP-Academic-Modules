// models/Admin.js
import pool from '../db/index.js'

class Admin {
  // Create a new admin
  static async create(adminData) {
    const { admin_id, admin_name, email, password } = adminData;
    
    const query = `
      INSERT INTO admin (admin_id, admin_name, email, password)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [admin_id, admin_name, email, password]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating admin: ${error.message}`);
    }
  }

  // Find admin by email
  static async findByEmail(email) {
    const query = 'SELECT * FROM admin WHERE email = $1';
    
    try {
      const result = await pool.query(query, [email]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding admin by email: ${error.message}`);
    }
  }

  // Find admin by ID
  static async findById(admin_id) {
    const query = 'SELECT * FROM admin WHERE admin_id = $1';
    
    try {
      const result = await pool.query(query, [admin_id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding admin by ID: ${error.message}`);
    }
  }

  // Get all admins
  static async findAll() {
    const query = 'SELECT admin_id, admin_name, email FROM admin';
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error fetching all admins: ${error.message}`);
    }
  }

  // Update admin
  static async update(admin_id, updateData) {
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

    values.push(admin_id);
    const query = `
      UPDATE admin 
      SET ${fields.join(', ')} 
      WHERE admin_id = $${paramCount}
      RETURNING *
    `;

    try {
      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating admin: ${error.message}`);
    }
  }

  // Delete admin
  static async delete(admin_id) {
    const query = 'DELETE FROM admin WHERE admin_id = $1 RETURNING *';
    
    try {
      const result = await pool.query(query, [admin_id]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting admin: ${error.message}`);
    }
  }
}

module.export = Admin;