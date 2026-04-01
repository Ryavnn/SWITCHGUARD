import React from 'react';
import { motion } from 'framer-motion';

const StatCard = ({ title, value, icon: Icon, colorClass, delay }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5, delay }}
    className="sg-card"
    style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}
  >
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div>
        <h4 style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px', margin: '0 0 8px 0' }}>
          {title}
        </h4>
        <h2 style={{ margin: 0, fontSize: '2rem', fontWeight: 700 }}>{value}</h2>
      </div>
      <div className={`icon-container ${colorClass}`} style={{ padding: '12px', borderRadius: '12px', background: 'rgba(255,255,255,0.05)' }}>
        <Icon size={28} />
      </div>
    </div>
  </motion.div>
);

export default StatCard;
