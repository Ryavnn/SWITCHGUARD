import api from './api';

const authService = {
  login: async (email, password) => {
    const res = await api.post('/api/auth/login', { email, password });
    if (res.data.access_token) {
      _persist(res.data.access_token, res.data.refresh_token, res.data.user);
    }
    return res.data;
  },

  register: async (name, email, password) => {
    const res = await api.post('/api/auth/register', { name, email, password });
    if (res.data.access_token) {
      _persist(res.data.access_token, res.data.refresh_token, res.data.user);
    }
    return res.data;
  },

  logout: () => {
    localStorage.removeItem('sg_token');
    localStorage.removeItem('sg_refresh_token');
    localStorage.removeItem('sg_user');
  },

  getCurrentUser: () => {
    const user = localStorage.getItem('sg_user');
    return user ? JSON.parse(user) : null;
  },

  getToken: () => localStorage.getItem('sg_token'),
};

const _persist = (token, refresh, user) => {
  localStorage.setItem('sg_token', token);
  localStorage.setItem('sg_refresh_token', refresh);
  localStorage.setItem('sg_user', JSON.stringify(user));
};

export default authService;
