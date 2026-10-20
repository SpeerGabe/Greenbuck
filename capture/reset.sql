-- ============================================================
-- GreenBuck capture seed: reset_state.sql
-- Applied by run_capture.py before every run.
-- Empties users and transactions, restarts their id sequences,
-- recreates the demo/demo123 account, and seeds a fixed
-- transaction history. timing_log is not touched.
-- ============================================================

BEGIN;

TRUNCATE public.transactions, public.users RESTART IDENTITY;

-- Argon2id hash of 'demo123' (argon2-cffi defaults: m=65536, t=3, p=4, same as main.py).
INSERT INTO public.users (username, password_hash, role) VALUES
  ('demo', '$argon2id$v=19$m=65536,t=3,p=4$DaFRzTAHy22RnvsSoKcmpw$+xOaXncTmLZ+3QPwgAW3VZP4k61wdgrI+mkVSiLdO9c', 'user');

INSERT INTO public.transactions (amount, category, "timestamp", merchant, username) VALUES
  (42.17, 'Groceries',     '2026-10-01', 'Kroger',     'demo'),
  (9.99,  'Entertainment', '2026-10-02', 'Netflix',    'demo'),
  (38.50, 'Gas',           '2026-10-04', 'Shell',      'demo'),
  (120.00,'Bills',         '2026-10-05', 'TVA',        'demo'),
  (14.25, 'Food',          '2026-10-07', 'Chick-fil-A','demo'),
  (23.80, 'Other',         '2026-10-09', NULL,         'demo');

COMMIT;
