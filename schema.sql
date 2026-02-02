-- Use a specific database (change name as needed)
CREATE DATABASE IF NOT EXISTS inventory CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
USE inventory;

-- ENUM types are declared inline in MySQL column definitions.

-- Users / Employees (id_number becomes barcode)
CREATE TABLE users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  id_number VARCHAR(64) NOT NULL UNIQUE,     -- used as barcode
  password_hash VARCHAR(255) NOT NULL,       -- store salted hash (bcrypt/argon2)
  role VARCHAR(32) NOT NULL DEFAULT 'employee',
  email VARCHAR(255),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  deleted_at DATETIME NULL,
  INDEX idx_users_id_number (id_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tools
CREATE TABLE tools (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  model VARCHAR(255),
  tool_number VARCHAR(64) UNIQUE,             -- optional human-friendly number (e.g. T-001)
  barcode VARCHAR(128) UNIQUE,                -- explicit barcode field (can equal tool_number or generated)
  status ENUM('available','borrowed','damaged','maintenance','lost') NOT NULL DEFAULT 'available',
  calibrate_due_date DATE,
  last_calibrated_at DATETIME NULL,
  notes TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  deleted_at DATETIME NULL,
  INDEX idx_tools_calibrate_due_date (calibrate_due_date),
  INDEX idx_tools_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Borrows (current/active borrow records)
CREATE TABLE borrows (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tool_id BIGINT UNSIGNED NOT NULL,
  borrower_id BIGINT UNSIGNED NULL,           -- employee who borrowed
  borrowed_by BIGINT UNSIGNED NULL,           -- staff who processed the borrow
  borrow_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  due_date DATE NULL,
  returned_at DATETIME NULL,
  returned_by BIGINT UNSIGNED NULL,
  status ENUM('borrowed','returned') NOT NULL DEFAULT 'borrowed',
  condition_on_borrow TEXT,
  condition_on_return TEXT,
  notes TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_borrows_borrower_id (borrower_id),
  INDEX idx_borrows_tool_id (tool_id),
  CONSTRAINT fk_borrows_tool FOREIGN KEY (tool_id) REFERENCES tools(id) ON DELETE RESTRICT,
  CONSTRAINT fk_borrows_borrower FOREIGN KEY (borrower_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_borrows_borrowed_by FOREIGN KEY (borrowed_by) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_borrows_returned_by FOREIGN KEY (returned_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Logs / audit trail
CREATE TABLE logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  action_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  action ENUM('borrow','return','calibrate','damage_report','repair','import','adjustment','delete') NOT NULL,
  tool_id BIGINT UNSIGNED NULL,
  user_id BIGINT UNSIGNED NULL,        -- subject (e.g. borrower)
  performed_by BIGINT UNSIGNED NULL,   -- who performed the action (scanner/operator)
  borrow_id BIGINT UNSIGNED NULL,
  prev_status ENUM('available','borrowed','damaged','maintenance','lost') NULL,
  new_status ENUM('available','borrowed','damaged','maintenance','lost') NULL,
  metadata JSON NULL,                  -- flexible for CSV row details, barcode payloads, etc.
  note TEXT,
  INDEX idx_logs_action_at (action_at),
  INDEX idx_logs_tool_id (tool_id),
  CONSTRAINT fk_logs_tool FOREIGN KEY (tool_id) REFERENCES tools(id) ON DELETE SET NULL,
  CONSTRAINT fk_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_logs_performed_by FOREIGN KEY (performed_by) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_logs_borrow FOREIGN KEY (borrow_id) REFERENCES borrows(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Calibration history
CREATE TABLE calibrations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tool_id BIGINT UNSIGNED NOT NULL,
  performed_by BIGINT UNSIGNED NULL,
  performed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  next_due_date DATE NULL,
  notes TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_calibrations_tool FOREIGN KEY (tool_id) REFERENCES tools(id) ON DELETE CASCADE,
  CONSTRAINT fk_calibrations_performed_by FOREIGN KEY (performed_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_calibrations_tool_id (tool_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CSV import batches
CREATE TABLE csv_imports (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  filename VARCHAR(255),
  imported_by BIGINT UNSIGNED NULL,
  imported_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  row_count INT NULL,
  errors JSON NULL,
  CONSTRAINT fk_csv_imports_by FOREIGN KEY (imported_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional: enforce one open borrow per tool.
-- MySQL CHECK constraints are supported starting with 8.0.16 (and may be enforced depending on version).
-- If you need strict enforcement on older versions, implement this with triggers or enforce at application level.
ALTER TABLE borrows
  ADD CONSTRAINT chk_borrow_open_consistency CHECK (
    NOT (status = 'borrowed' AND returned_at IS NOT NULL)
  );

-- Useful additional indexes
CREATE INDEX idx_tools_tool_number ON tools(tool_number);
CREATE INDEX idx_tools_barcode ON tools(barcode);
