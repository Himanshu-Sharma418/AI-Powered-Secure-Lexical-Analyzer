-- Basic SQL statements
SELECT * FROM users;
SELECT name, email FROM customers WHERE id = 1;

-- Potential injection patterns
SELECT * FROM users WHERE username = 'admin' OR '1'='1';
SELECT * FROM users WHERE password = "" OR ""="";

-- UNION-based attacks
SELECT * FROM products UNION SELECT username, password FROM users;