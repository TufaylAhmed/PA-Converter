-- Ensure factory admin (email=admin / password=paloalto) can authenticate.
-- Sentinel returns "Incorrect user or password" when activations.completed=0
-- or when the stored bcrypt hash was corrupted (e.g. shell `$` expansion).

INSERT INTO users (
  id, email, password, permissions, last_login, first_name, last_name,
  created_at, updated_at, location_id, location_type, timezone, active
)
SELECT
  1, 'admin',
  '$2y$10$Nk2/jJmmirfgfLLPEGJ7.erkiaVCgRGUZvSPi5wG/gg8SqYFBvYPO',
  NULL, NOW(), 'admin', 'admin', NOW(), NOW(), 0, 'local', 'UTC', 1
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin' OR id = 1);

UPDATE users
SET active = 1,
    location_type = 'local',
    password = IF(
      password IS NULL
        OR password NOT LIKE '$2%'
        OR CHAR_LENGTH(password) < 59,
      '$2y$10$Nk2/jJmmirfgfLLPEGJ7.erkiaVCgRGUZvSPi5wG/gg8SqYFBvYPO',
      password
    )
WHERE email = 'admin' OR id = 1;

INSERT INTO activations (user_id, code, completed, completed_at, created_at, updated_at)
SELECT u.id, 'pa-converter-default', 1, NOW(), NOW(), NOW()
FROM users u
WHERE (u.email = 'admin' OR u.id = 1)
  AND NOT EXISTS (SELECT 1 FROM activations a WHERE a.user_id = u.id);

UPDATE activations a
INNER JOIN users u ON u.id = a.user_id AND (u.email = 'admin' OR u.id = 1)
SET a.completed = 1,
    a.completed_at = COALESCE(a.completed_at, NOW());

INSERT IGNORE INTO role_users (user_id, role_id, created_at, updated_at)
SELECT u.id, 3, NOW(), NOW()
FROM users u
WHERE u.email = 'admin' OR u.id = 1;

DELETE t FROM throttle t
INNER JOIN users u ON u.id = t.user_id
WHERE u.email = 'admin' OR u.id = 1;
