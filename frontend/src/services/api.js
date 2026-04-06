/**
 * Centralised axios instance for SwitchGuard API calls.
 *
 * - Automatically attaches the stored JWT to every request.
 * - On 401 responses, attempts a silent token refresh via the stored
 *   refresh_token, then retries the original request once.
 * - On second 401 (refresh expired), clears storage and redirects to /login.
 */
import axios from 'axios';

const BASE_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,           // 60 s — scans can be slow
});

// ── Request interceptor: attach token ──────────────────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sg_token');
    if (token && token !== 'undefined') {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error),
);

// ── Response interceptor: handle 401 / token refresh ──────────────────────
let isRefreshing = false;
let failedQueue  = [];    // queued requests while a refresh is in progress

const processQueue = (error, token = null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else       resolve(token);
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('sg_refresh_token');
      if (!refreshToken) {
        // No refresh token — force re-login
        _clearAndRedirect();
        return Promise.reject(error);
      }

      if (isRefreshing) {
        // Queue this request until the refresh resolves
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          return api(originalRequest);
        }).catch((err) => Promise.reject(err));
      }

      isRefreshing = true;
      try {
        const res = await axios.post(`${BASE_URL}/api/auth/refresh`, {
          refresh_token: refreshToken,
        });
        const newToken = res.data.access_token;
        localStorage.setItem('sg_token', newToken);
        api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
        axios.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
        processQueue(null, newToken);
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        _clearAndRedirect();
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // ── Non-401 Error Handling ──────────────────────────────────────────────
    if (!error.response) {
      // Truly a Network Error (unreachable, CORS, or local connection issues)
      error.message = "The security backend is unreachable. Please verify that the server is running on " + BASE_URL;
    } else if (error.response.status >= 500) {
      error.message = "A critical server error occurred (500). Please check the backend logs.";
    } else if (error.response.data && error.response.data.detail) {
      // Exact FastAPI detail message (e.g. "Invalid credentials")
      error.message = error.response.data.detail;
    }

    return Promise.reject(error);
  },
);

function _clearAndRedirect() {
  localStorage.removeItem('sg_token');
  localStorage.removeItem('sg_refresh_token');
  localStorage.removeItem('sg_user');
  delete axios.defaults.headers.common['Authorization'];
  // Soft redirect — avoids hard dependency on react-router
  if (window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
}

export default api;
