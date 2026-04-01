import api from './api';

const reportService = {
  download: async (jobId, type) => {
    try {
      const res = await api.get(`/api/reports/${jobId}/${type}`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `SwitchGuard_Report_${jobId.substring(0,8)}.${type}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      return true;
    } catch (err) {
      console.error('Report Download Error', err);
      throw err;
    }
  },
};

export default reportService;
