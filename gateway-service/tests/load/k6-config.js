// gateway-service/tests/load/k6-config.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const successfulRequests = new Counter('successful_requests');
const failedRequests = new Counter('failed_requests');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 20 }, // Ramp up to 20 users
    { duration: '5m', target: 20 }, // Stay at 20 users
    { duration: '2m', target: 50 }, // Ramp up to 50 users
    { duration: '5m', target: 50 }, // Stay at 50 users
    { duration: '2m', target: 100 }, // Ramp up to 100 users
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '3m', target: 0 },   // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must be below 500ms
    http_req_failed: ['rate<0.05'],   // Error rate must be below 5%
    errors: ['rate<0.05'],            // Custom error rate below 5%
    response_time: ['p(95)<500'],     // Custom response time threshold
  },
};

// Base URL for the gateway
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

// Test data
const testUsers = [
  { email: 'test1@example.com', password: 'password123' },
  { email: 'test2@example.com', password: 'password123' },
  { email: 'test3@example.com', password: 'password123' },
];

const testComments = [
  'This product is amazing! Great customer service.',
  'The shipping was delayed and the package was damaged.',
  'Good value for money, would recommend to others.',
  'The user interface is confusing and hard to navigate.',
  'Excellent quality and fast delivery.',
];

let authTokens = [];

// Setup function - runs once at the start
export function setup() {
  console.log('Setting up load test...');
  
  // Pre-authenticate users for testing
  const tokens = [];
  
  for (const user of testUsers) {
    const loginRes = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify(user), {
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (loginRes.status === 200) {
      const token = loginRes.json('data.token');
      if (token) {
        tokens.push(token);
      }
    }
  }
  
  console.log(`Authenticated ${tokens.length} users for testing`);
  return { tokens };
}

// Main test function
export default function (data) {
  const token = data.tokens[Math.floor(Math.random() * data.tokens.length)];
  
  // Test different scenarios with weighted distribution
  const scenario = Math.random();
  
  if (scenario < 0.3) {
    testHealthEndpoints();
  } else if (scenario < 0.5) {
    testAuthenticationFlow();
  } else if (scenario < 0.7) {
    testCommentProcessing(token);
  } else if (scenario < 0.85) {
    testIndustryDataAccess();
  } else {
    testNPSAnalytics(token);
  }
  
  // Sleep between requests (1-3 seconds)
  sleep(Math.random() * 2 + 1);
}

function testHealthEndpoints() {
  const responses = http.batch([
    ['GET', `${BASE_URL}/health`],
    ['GET', `${BASE_URL}/api/status`],
    ['GET', `${BASE_URL}/health/services`],
  ]);
  
  responses.forEach((res, index) => {
    const isSuccess = check(res, {
      [`health endpoint ${index} status is 200`]: (r) => r.status === 200,
      [`health endpoint ${index} response time < 200ms`]: (r) => r.timings.duration < 200,
    });
    
    recordMetrics(res, isSuccess);
  });
}

function testAuthenticationFlow() {
  // Test user login
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  
  const loginRes = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify(user),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { endpoint: 'auth_login' },
    }
  );
  
  const loginSuccess = check(loginRes, {
    'login status is 200': (r) => r.status === 200,
    'login returns token': (r) => r.json('data.token') !== undefined,
    'login response time < 1s': (r) => r.timings.duration < 1000,
  });
  
  recordMetrics(loginRes, loginSuccess);
  
  // If login successful, test token verification
  if (loginSuccess && loginRes.json('data.token')) {
    const token = loginRes.json('data.token');
    
    const verifyRes = http.get(`${BASE_URL}/api/auth/verify`, {
      headers: { Authorization: `Bearer ${token}` },
      tags: { endpoint: 'auth_verify' },
    });
    
    const verifySuccess = check(verifyRes, {
      'verify status is 200': (r) => r.status === 200,
      'verify returns valid user': (r) => r.json('data.valid') === true,
      'verify response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    recordMetrics(verifyRes, verifySuccess);
  }
}

function testCommentProcessing(token) {
  if (!token) return;
  
  const comments = [];
  const numComments = Math.floor(Math.random() * 5) + 1; // 1-5 comments
  
  for (let i = 0; i < numComments; i++) {
    comments.push(testComments[Math.floor(Math.random() * testComments.length)]);
  }
  
  const payload = {
    comments,
    apiKey: 'sk-test-load-testing-key-12345',
    industry: 'SaaS/Technology',
  };
  
  const categorizeRes = http.post(
    `${BASE_URL}/api/comments/categorize`,
    JSON.stringify(payload),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      tags: { endpoint: 'comment_categorize' },
    }
  );
  
  const categorizeSuccess = check(categorizeRes, {
    'categorize status is 200': (r) => r.status === 200,
    'categorize returns job ID': (r) => r.json('data.jobId') !== undefined,
    'categorize response time < 2s': (r) => r.timings.duration < 2000,
  });
  
  recordMetrics(categorizeRes, categorizeSuccess);
  
  // If categorization successful, check job status
  if (categorizeSuccess && categorizeRes.json('data.jobId')) {
    const jobId = categorizeRes.json('data.jobId');
    
    sleep(1); // Wait a bit before checking status
    
    const statusRes = http.get(
      `${BASE_URL}/api/comments/job/${jobId}/status`,
      {
        headers: { Authorization: `Bearer ${token}` },
        tags: { endpoint: 'comment_status' },
      }
    );
    
    const statusSuccess = check(statusRes, {
      'status check is 200': (r) => r.status === 200,
      'status returns job info': (r) => r.json('data.jobId') === jobId,
      'status response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    recordMetrics(statusRes, statusSuccess);
  }
}

function testIndustryDataAccess() {
  // Get list of industries
  const industriesRes = http.get(`${BASE_URL}/api/industries`, {
    tags: { endpoint: 'industries_list' },
  });
  
  const industriesSuccess = check(industriesRes, {
    'industries status is 200': (r) => r.status === 200,
    'industries returns data': (r) => r.json('data.industries') !== undefined,
    'industries response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  recordMetrics(industriesRes, industriesSuccess);
  
  // Get categories for a specific industry
  const industry = 'SaaS/Technology';
  const categoriesRes = http.get(
    `${BASE_URL}/api/industries/${encodeURIComponent(industry)}/categories`,
    {
      tags: { endpoint: 'industry_categories' },
    }
  );
  
  const categoriesSuccess = check(categoriesRes, {
    'categories status is 200': (r) => r.status === 200,
    'categories returns data': (r) => r.json('data.categories') !== undefined,
    'categories response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  recordMetrics(categoriesRes, categoriesSuccess);
}

function testNPSAnalytics(token) {
  if (!token) return;
  
  const userId = 'test-user-id';
  
  // Get NPS dashboard
  const dashboardRes = http.get(
    `${BASE_URL}/api/nps/dashboard/${userId}`,
    {
      headers: { Authorization: `Bearer ${token}` },
      tags: { endpoint: 'nps_dashboard' },
    }
  );
  
  const dashboardSuccess = check(dashboardRes, {
    'dashboard status is 200': (r) => r.status === 200,
    'dashboard returns NPS score': (r) => r.json('data.npsScore') !== undefined,
    'dashboard response time < 1s': (r) => r.timings.duration < 1000,
  });
  
  recordMetrics(dashboardRes, dashboardSuccess);
  
  // Test NPS upload
  const uploadPayload = {
    npsData: [
      { customerId: 'cust1', npsScore: 9, comments: 'Great service!' },
      { customerId: 'cust2', npsScore: 7, comments: 'Good overall' },
    ],
  };
  
  const uploadRes = http.post(
    `${BASE_URL}/api/nps/upload`,
    JSON.stringify(uploadPayload),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      tags: { endpoint: 'nps_upload' },
    }
  );
  
  const uploadSuccess = check(uploadRes, {
    'upload status is 200': (r) => r.status === 200,
    'upload returns upload ID': (r) => r.json('data.uploadId') !== undefined,
    'upload response time < 2s': (r) => r.timings.duration < 2000,
  });
  
  recordMetrics(uploadRes, uploadSuccess);
}

function recordMetrics(response, isSuccess) {
  // Record custom metrics
  responseTime.add(response.timings.duration);
  errorRate.add(!isSuccess);
  
  if (isSuccess) {
    successfulRequests.add(1);
  } else {
    failedRequests.add(1);
  }
}

// Teardown function - runs once at the end
export function teardown(data) {
  console.log('Load test completed');
  console.log(`Total tokens used: ${data.tokens.length}`);
}

// Stress test configuration
export const stressOptions = {
  stages: [
    { duration: '1m', target: 50 },   // Ramp up
    { duration: '3m', target: 100 },  // Normal load
    { duration: '2m', target: 200 },  // High load
    { duration: '3m', target: 300 },  // Stress load
    { duration: '2m', target: 400 },  // Peak stress
    { duration: '3m', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<1000'], // Relaxed threshold for stress test
    http_req_failed: ['rate<0.1'],     // Allow higher error rate
  },
};

// Spike test configuration
export const spikeOptions = {
  stages: [
    { duration: '30s', target: 20 },   // Normal load
    { duration: '1m', target: 500 },   // Spike up
    { duration: '30s', target: 20 },   // Back to normal
    { duration: '1m', target: 500 },   // Another spike
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'], // Very relaxed for spike test
    http_req_failed: ['rate<0.2'],     // Allow higher error rate
  },
};