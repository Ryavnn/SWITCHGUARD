/**
 * Defines the navigation structure based on user roles (Admin, Analyst, User).
 */
export const getNavItems = (role) => {
  const isGlobal = role === 'Admin' || role === 'Analyst';
  const prefix = isGlobal ? `/dashboard/${role.toLowerCase()}` : '/dashboard/user';

  const items = [
    { to: prefix, icon: '▪', label: role === 'Admin' ? 'Admin Dashboard' : role === 'Analyst' ? 'Analyst View' : 'My Dashboard' }
  ];

  if (role === 'Admin' || role === 'Analyst') {
    items.push({ to: '/remediation', icon: '⚡', label: 'Remediation Queue' });
    items.push({ to: '/analytics', icon: '📈', label: 'Intelligence' });
  }

  if (role === 'Admin') {
    items.push({ to: '/history', icon: '≡', label: 'All Scans' });
    items.push({ to: '/admin/users', icon: '👤', label: 'Users & Roles' });
    items.push({ to: '/admin/assets', icon: '🖥', label: 'Global Assets' });
    items.push({ to: '/portal', icon: '🏢', label: 'Client Portal' });
    items.push({ to: '/admin/settings', icon: '⚙', label: 'Platform Settings' });
  } else {
    items.push({ to: '/history', icon: '≡', label: 'My Scans' });
    if (role === 'User') {
      items.push({ to: '/portal', icon: '🏢', label: 'My Portal' });
    }
  }

  // Insert New Scan at index 1
  items.splice(1, 0, { to: '/scan', icon: '⊕', label: 'New Scan' }); 
  
  return items;
};
