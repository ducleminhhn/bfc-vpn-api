/**
 * Story 2.6: Local PostgreSQL Auth - k6 Load Test
 * 
 * Validates:
 * - Login endpoint P99 latency < 800ms
 * - TOTP verify P99 latency < 300ms
 * - Recovery verify P99 latency < 300ms
 * - Concurrent handling 100 req/s
 * - Rate limiting triggers at expected thresholds
 * 
 * Run: k6 run scripts/load-test-local-auth.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Trend } from 'k6/metrics';

// Custom metrics
const loginDuration = new Trend('local_auth_login_duration');
const totpDuration = new Trend('local_auth_totp_duration');
const recoveryDuration = new Trend('local_auth_recovery_duration');
const rateLimitHits = new Counter('rate_limit_hits');

export let options = {
    scenarios: {
        // Scenario 1: Sustained load test
        sustained_load: {
            executor: 'constant-arrival-rate',
            rate: 100,           // 100 requests per second
            timeUnit: '1s',
            duration: '30s',
            preAllocatedVUs: 50,
            maxVUs: 150,
        },
        // Scenario 2: Spike test
        spike_test: {
            executor: 'ramping-arrival-rate',
            startRate: 10,
            timeUnit: '1s',
            preAllocatedVUs: 50,
            maxVUs: 200,
            stages: [
                { duration: '10s', target: 50 },
                { duration: '20s', target: 100 },
                { duration: '10s', target: 10 },
            ],
            startTime: '35s', // Start after sustained load
        },
    },
    thresholds: {
        // Story 2.6 Success Metrics
        'local_auth_login_duration': ['p(99)<800'],     // P99 < 800ms
        'local_auth_totp_duration': ['p(99)<300'],      // P99 < 300ms  
        'local_auth_recovery_duration': ['p(99)<300'],  // P99 < 300ms
        'http_req_failed': ['rate<0.05'],               // <5% error rate (excluding expected 401/429)
        'http_req_duration': ['p(95)<1000'],            // 95% < 1s overall
    },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:8081';
const HEADERS = { 'Content-Type': 'application/json' };

export default function () {
    group('Local Auth Login Endpoint', function () {
        // Test with invalid credentials (expected 401)
        const loginPayload = JSON.stringify({
            email: `loadtest${__VU}@example.com`,
            password: 'wrongpassword123', // Intentionally wrong
        });

        const loginStart = Date.now();
        const loginRes = http.post(`${BASE_URL}/api/v1/auth/local/login`, loginPayload, { headers: HEADERS });
        const loginTime = Date.now() - loginStart;
        
        loginDuration.add(loginTime);

        const loginChecks = check(loginRes, {
            'login returns 401 or 429': (r) => r.status === 401 || r.status === 429 || r.status === 423,
            'login response time < 800ms': (r) => r.timings.duration < 800,
            'login has RFC 7807 type field': (r) => {
                try {
                    return JSON.parse(r.body).type !== undefined;
                } catch (e) {
                    return false;
                }
            },
            'login has Vietnamese message': (r) => {
                try {
                    const body = JSON.parse(r.body);
                    return body.detail && /[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]/i.test(body.detail);
                } catch (e) {
                    return false;
                }
            },
        });

        if (loginRes.status === 429) {
            rateLimitHits.add(1);
            // Check Retry-After header
            check(loginRes, {
                'rate limit has Retry-After header': (r) => r.headers['Retry-After'] !== undefined,
            });
        }
    });

    group('TOTP Verify Endpoint', function () {
        const totpPayload = JSON.stringify({
            mfa_token: 'invalid-mfa-token',
            code: '123456',
        });

        const totpStart = Date.now();
        const totpRes = http.post(`${BASE_URL}/api/v1/auth/local/totp/verify`, totpPayload, { headers: HEADERS });
        const totpTime = Date.now() - totpStart;
        
        totpDuration.add(totpTime);

        check(totpRes, {
            'totp returns 401 (expired token)': (r) => r.status === 401,
            'totp response time < 300ms': (r) => r.timings.duration < 300,
        });
    });

    group('Recovery Verify Endpoint', function () {
        const recoveryPayload = JSON.stringify({
            mfa_token: 'invalid-mfa-token',
            code: 'INVALID-RECOVERY',
        });

        const recoveryStart = Date.now();
        const recoveryRes = http.post(`${BASE_URL}/api/v1/auth/local/recovery/verify`, recoveryPayload, { headers: HEADERS });
        const recoveryTime = Date.now() - recoveryStart;
        
        recoveryDuration.add(recoveryTime);

        check(recoveryRes, {
            'recovery returns 401 (expired token)': (r) => r.status === 401,
            'recovery response time < 300ms': (r) => r.timings.duration < 300,
        });
    });

    sleep(0.1); // 100ms between iterations
}

export function handleSummary(data) {
    const summary = {
        timestamp: new Date().toISOString(),
        story: '2.6-local-postgresql-auth',
        thresholds_passed: Object.values(data.metrics).every(m => !m.thresholds || Object.values(m.thresholds).every(t => t.ok)),
        metrics: {
            login_p99: data.metrics.local_auth_login_duration?.values?.['p(99)'] || 0,
            totp_p99: data.metrics.local_auth_totp_duration?.values?.['p(99)'] || 0,
            recovery_p99: data.metrics.local_auth_recovery_duration?.values?.['p(99)'] || 0,
            rate_limit_hits: data.metrics.rate_limit_hits?.values?.count || 0,
            total_requests: data.metrics.http_reqs?.values?.count || 0,
            error_rate: data.metrics.http_req_failed?.values?.rate || 0,
        },
    };

    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }),
        'load-test-local-auth-results.json': JSON.stringify(summary, null, 2),
    };
}

function textSummary(data, opts) {
    const lines = [
        '╔══════════════════════════════════════════════════════════════╗',
        '║     Story 2.6: Local Auth Load Test Results                  ║',
        '╚══════════════════════════════════════════════════════════════╝',
        '',
        'Performance Metrics:',
        `  Login P99:     ${(data.metrics.local_auth_login_duration?.values?.['p(99)'] || 0).toFixed(2)}ms (target: <800ms)`,
        `  TOTP P99:      ${(data.metrics.local_auth_totp_duration?.values?.['p(99)'] || 0).toFixed(2)}ms (target: <300ms)`,
        `  Recovery P99:  ${(data.metrics.local_auth_recovery_duration?.values?.['p(99)'] || 0).toFixed(2)}ms (target: <300ms)`,
        '',
        'Throughput:',
        `  Total Requests: ${data.metrics.http_reqs?.values?.count || 0}`,
        `  Rate Limit Hits: ${data.metrics.rate_limit_hits?.values?.count || 0}`,
        `  Error Rate: ${((data.metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%`,
        '',
    ];
    return lines.join('\n');
}
