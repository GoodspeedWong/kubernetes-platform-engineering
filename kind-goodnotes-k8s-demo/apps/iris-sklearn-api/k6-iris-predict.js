import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

/**
 * Custom Metrics
 */
const predictLatency = new Trend('iris_predict_latency');
const errorRate = new Rate('iris_predict_error_rate');

export const options = {
  scenarios: {
    iris_high_rps: {
      executor: 'constant-arrival-rate',
      rate: __ENV.TARGET_RPS ? Number(__ENV.TARGET_RPS) : 2000,
      timeUnit: '1s',
      duration: __ENV.TEST_DURATION || '5m',
      preAllocatedVUs: 200,
      maxVUs: 2000,
    },
  },

  thresholds: {
    http_req_failed: ['rate<0.01'],
    iris_predict_latency: ['p(95)<500', 'p(99)<800'],
  },
};

const url = 'http://iris.localhost:8080/predict';

const payload = JSON.stringify({
  features: [5.1, 3.5, 1.4, 0.2],
});

const params = {
  headers: {
    'Content-Type': 'application/json',
    'Host': 'iris.localhost',
  },
  tags: {
    service: 'iris-sklearn-api',
    endpoint: '/predict',
    method: 'POST',
    scenario: 'k6_high_concurrency',
  },
};

export default function () {
  const res = http.post(url, payload, params);

  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
    'has json response': (r) => r.headers['Content-Type'] && r.headers['Content-Type'].includes('application/json'),
    'has prediction': (r) => {
      try {
        return JSON.parse(r.body).prediction !== undefined;
      } catch (e) {
        return false;
      }
    },
  });

  predictLatency.add(res.timings.duration);
  errorRate.add(!ok);
}