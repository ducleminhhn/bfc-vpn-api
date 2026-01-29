-- name: HealthCheck :one
SELECT 1 AS ok;

-- name: HealthCheckWithRLS :one
SELECT current_setting('app.current_tenant_id', true) IS NOT NULL AS rls_configured;
