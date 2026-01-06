use crate::utils::Result;
use anyhow::Context;
use rusqlite::Connection;
use std::path::Path;

pub struct DatabasePool {
    db_path: String,
}

impl DatabasePool {
    pub fn new(db_path: &str) -> Result<Self> {
        if !Path::new(db_path).exists() {
            return Err(anyhow::anyhow!("Database file not found: {}", db_path).into());
        }

        Ok(Self {
            db_path: db_path.to_string(),
        })
    }

    pub fn get_connection(&self) -> Result<Connection> {
        Ok(Connection::open(&self.db_path)
            .with_context(|| format!("Failed to open database: {}", self.db_path))?)
    }
}

pub struct DatabaseBase {
    pool: DatabasePool,
    #[allow(dead_code)]
    existed_tables: Vec<String>,
}

impl DatabaseBase {
    pub fn new(db_path: &str) -> Result<Self> {
        let pool = DatabasePool::new(db_path)?;
        let db = Self {
            pool,
            existed_tables: Vec::new(),
        };
        // db.load_tables()?; // This line is removed as load_tables is replaced/removed
        Ok(db)
    }

    pub fn get_connection(&self) -> Result<Connection> {
        self.pool.get_connection()
    }

    // fn load_tables(&mut self) -> Result<()> { // This function is removed
    //     let conn = self.pool.get_connection()?;
    //     let mut stmt = conn.prepare(
    //         "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
    //     )?;
        
    //     let tables = stmt.query_map([], |row| {
    //         Ok(row.get::<_, String>(0)?)
    //     })?;

    //     self.existed_tables.clear();
    //     for table in tables {
    //         self.existed_tables.push(table?);
    //     }

    //     Ok(())
    // }

    /// 检查表是否存在
    pub fn table_exists(&self, table_name: &str) -> bool {
        if let Ok(conn) = self.get_connection() {
            // Explicitly type the statement to help inference
            let mut stmt = match conn.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
            ) {
                Ok(stmt) => stmt,
                Err(_) => return false,
            };
            
            return stmt.exists([table_name]).unwrap_or(false);
        }
        false
    }
    
    /// 获取所有表名
    #[allow(dead_code)]
    pub fn get_tables(&mut self) -> Result<Vec<String>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
        )?;
        
        let tables = stmt.query_map([], |row| {
            Ok(row.get::<_, String>(0)?)
        })?;

        for table in tables {
            self.existed_tables.push(table?);
        }
        
        Ok(self.existed_tables.clone())
    }

    /// 执行查询
    pub fn execute_query<T, F>(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
        mapper: F,
    ) -> Result<Vec<T>>
    where
        F: FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
    {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params, mapper)?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    /// 执行更新
    pub fn execute(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<usize> {
        let conn = self.get_connection()?;
        let count = conn.execute(sql, params)?;
        Ok(count)
    }

    /// 执行批处理
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        let conn = self.get_connection()?;
        conn.execute_batch(sql)?;
        Ok(())
    }

    /// 获取数据库路径
    pub fn get_db_path(&self) -> &str {
        &self.pool.db_path
    }
}

