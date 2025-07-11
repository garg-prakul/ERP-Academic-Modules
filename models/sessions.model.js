import pool from '../db/index.js'

class UserSessions {
  static async create(sessionData) {
    const { sid, sess, expire } = sessionData;
    
    const query = `
      INSERT INTO user_sessions (sid, sess, expire)
      VALUES ($1, $2, $3)
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [sid, sess, expire]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error creating session: ${error.message}`);
    }
  }

  static async findBySid(sid) {
    const query = 'SELECT * FROM user_sessions WHERE sid = $1';
    
    try {
      const result = await pool.query(query, [sid]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error finding session by SID: ${error.message}`);
    }
  }

  static async update(sid, sessionData) {
    const { sess, expire } = sessionData;
    
    const query = `
      UPDATE user_sessions 
      SET sess = $1, expire = $2 
      WHERE sid = $3
      RETURNING *
    `;
    
    try {
      const result = await pool.query(query, [sess, expire, sid]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error updating session: ${error.message}`);
    }
  }

  static async delete(sid) {
    const query = 'DELETE FROM user_sessions WHERE sid = $1 RETURNING *';
    
    try {
      const result = await pool.query(query, [sid]);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error deleting session: ${error.message}`);
    }
  }

  static async deleteExpired() {
    const query = 'DELETE FROM user_sessions WHERE expire < NOW() RETURNING *';
    
    try {
      const result = await pool.query(query);
      return result.rows;
    } catch (error) {
      throw new Error(`Error deleting expired sessions: ${error.message}`);
    }
  }

  static async getActiveSessions() {
    const query = 'SELECT COUNT(*) as active_sessions FROM user_sessions WHERE expire > NOW()';
    
    try {
      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      throw new Error(`Error getting active sessions count: ${error.message}`);
    }
  }
}

module.export = UserSessions;