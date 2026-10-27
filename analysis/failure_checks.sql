-- Checks that the failed run (AES-GCM, random padding, run 21, 2026-10-25 04:22:27 Central)
-- left nothing behind and did not change the runs captured after it.
-- Usage: psql -d greenbuck_research -f failure_checks.sql

-- 1. The failure as the batch log recorded it.
SELECT logged_at, encryption, mitigation, run_number, status, detail
FROM batch_log WHERE status <> 'ok';

-- 2. Rows in iterations that belong to no run (a partly written run would leave these).
SELECT count(*) AS stray_iteration_rows
FROM iterations i LEFT JOIN runs r USING (run_id)
WHERE r.run_id IS NULL;

-- 3. Database state each run started from (one value means every run started from the same seed).
SELECT seed_sha, count(*) AS runs FROM runs GROUP BY seed_sha;

-- 4. User actions the phone reported as failed, across all runs.
SELECT count(*) AS actions, count(*) FILTER (WHERE NOT ok) AS failed_actions FROM iterations;

-- 5. Runs before vs after the failure. Each request's server response time and response size
--    are divided by the median for the same cipher, defense and request type, so 1.000 means
--    typical. Each run's value is the median over its requests.
WITH med AS (
  SELECT encryption, mitigation, label,
         percentile_cont(0.5) WITHIN GROUP (ORDER BY ttfb_ms) AS med_ttfb,
         percentile_cont(0.5) WITHIN GROUP (ORDER BY resp_bytes) AS med_bytes
  FROM exchanges GROUP BY encryption, mitigation, label),
per_run AS (
  SELECT e.run_id,
         percentile_cont(0.5) WITHIN GROUP (ORDER BY e.ttfb_ms / m.med_ttfb) AS rel_time,
         percentile_cont(0.5) WITHIN GROUP (ORDER BY e.resp_bytes / m.med_bytes) AS rel_bytes
  FROM exchanges e JOIN med m USING (encryption, mitigation, label)
  GROUP BY e.run_id)
SELECT CASE WHEN r.start_time < '2026-10-25 04:22:27-05' THEN '1 before failure'
            ELSE '2 after failure' END AS period,
       count(*) AS runs,
       round(avg(p.rel_time)::numeric, 3) AS avg_rel_time,
       round(stddev(p.rel_time)::numeric, 3) AS sd_rel_time,
       round(avg(p.rel_bytes)::numeric, 3) AS avg_rel_bytes
FROM per_run p JOIN runs r USING (run_id)
GROUP BY 1 ORDER BY 1;
