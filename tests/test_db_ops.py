import os
import sqlite3
import pytest

from wgpl import core
from wgpl.exceptions import WgplException

def test_dump_database(capsys: pytest.CaptureFixture, wg0_interface: str) -> None:
    # `wg0_interface` fixture creates a database and populates it with 'wg0'
    core.dump_database()
    
    captured = capsys.readouterr()
    
    # Check stderr for the security hint
    assert "Hint: Redirect this output" in captured.err
    assert "chmod 600" in captured.err
    
    # Check stdout for the SQL dump
    assert "BEGIN TRANSACTION;" in captured.out
    assert "CREATE TABLE interfaces" in captured.out
    assert "INSERT INTO \"interfaces\" VALUES('wg0'" in captured.out
    assert "COMMIT;" in captured.out

def test_restore_database_success(wgpl_db: str) -> None:
    # First, let's create a known SQL state
    sql_script = """
    BEGIN TRANSACTION;
    CREATE TABLE IF NOT EXISTS "test_table" (id INTEGER PRIMARY KEY, value TEXT);
    INSERT INTO "test_table" VALUES(1, 'restored_data');
    COMMIT;
    """
    
    core.restore_database(sql_script)
    
    # Verify the database was restored successfully
    with sqlite3.connect(wgpl_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM test_table WHERE id = 1")
        result = cursor.fetchone()
        
    assert result is not None
    assert result[0] == 'restored_data'
    
    # Verify temp and wal files are cleaned up
    assert not os.path.exists(f"{wgpl_db}.tmp")
    assert not os.path.exists(f"{wgpl_db}-wal")

def test_restore_database_failure_invalid_syntax(wgpl_db: str) -> None:
    # Create a table in the live DB to check if it survives the failed restore
    with sqlite3.connect(wgpl_db) as conn:
        conn.execute("CREATE TABLE original (id INT)")
        
    invalid_sql = "BEGIN TRANSACTION; CREATE TABL ERROR SYNTAX;"
    
    with pytest.raises(WgplException, match="Failed to restore database"):
        core.restore_database(invalid_sql)
        
    # Verify the live database was NOT overwritten
    with sqlite3.connect(wgpl_db) as conn:
        cursor = conn.cursor()
        # This will fail if the table doesn't exist, meaning the original DB was overwritten
        cursor.execute("SELECT * FROM original") 
        
    # Verify temp file is cleaned up after failure
    assert not os.path.exists(f"{wgpl_db}.tmp")
