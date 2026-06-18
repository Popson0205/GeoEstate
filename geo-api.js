// GeoEstate — Unified API Module v2.0
// Handles: public properties, owner auth, SSE sync, enquiries
// Include after main scripts: <script src="geo-api.js"></script>

(function(window) {
  'use strict';

  const GEO_API = 'https://geoestate.onrender.com';
  const ADMIN_TOKEN_KEY = 'geo_admin_token';
  const OWNER_SESSION_KEY = 'geo_owner_session';

  // ── Helper ──────────────────────────────────────────────────────
  function getAdminToken() {
    return localStorage.getItem(ADMIN_TOKEN_KEY) || window.GEO_ADMIN_TOKEN || '';
  }

  function adminHeaders() {
    return {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + getAdminToken()
    };
  }

  function ownerHeaders() {
    const s = getOwnerSession();
    return {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + (s ? s.token : '')
    };
  }

  function getOwnerSession() {
    try {
      const s = localStorage.getItem(OWNER_SESSION_KEY);
      return s ? JSON.parse(s) : null;
    } catch(e) { return null; }
  }

  function setOwnerSession(data) {
    localStorage.setItem(OWNER_SESSION_KEY, JSON.stringify(data));
  }

  function clearOwnerSession() {
    localStorage.removeItem(OWNER_SESSION_KEY);
  }

  // ── Map DB property to frontend format ─────────────────────────
  function mapProperty(p) {
    const lt = p.listing_type || p.type || 'rent';
    let displayPrice = p.price || '';
    if (lt === 'rent' && p.monthly_rent) displayPrice = '₦' + Number(p.monthly_rent).toLocaleString() + '/mo';
    else if (lt === 'buy' && p.sale_price) displayPrice = '₦' + Number(p.sale_price).toLocaleString();
    else if (lt === 'lease' && p.lease_price) displayPrice = '₦' + Number(p.lease_price).toLocaleString() + ' lease';

    let images = [];
    try { images = typeof p.images === 'string' ? JSON.parse(p.images) : (p.images || []); } catch(e) {}
    let amenities = [];
    try { amenities = typeof p.amenities === 'string' ? JSON.parse(p.amenities) : (p.amenities || []); } catch(e) {}

    return {
      id: p.id,
      listing_type: lt,
      type: lt,
      title: p.title,
      price: displayPrice || p.price || '—',
      monthly_rent: p.monthly_rent,
      sale_price: p.sale_price,
      lease_price: p.lease_price,
      location: p.address || p.lga || p.state || '—',
      state: p.state || '',
      lga: p.lga || '',
      address: p.address || '',
      img: p.img || (images[0] || ''),
      images: images,
      beds: p.bedrooms || 0,
      baths: p.bathrooms || 0,
      sqm: p.size_sqm || 0,
      description: p.description || '',
      amenities: amenities,
      units: p.units || [],
      owner: p.owner || '',
      owner_id: p.owner_id || '',
      verified: true,
      lat: 0, lng: 0,
      tags: [], video: false
    };
  }

  // ── Public API ──────────────────────────────────────────────────

  async function loadPublicProperties(opts) {
    opts = opts || {};
    let url = GEO_API + '/properties';
    const params = [];
    if (opts.type && opts.type !== 'all') params.push('type=' + opts.type);
    if (opts.state) params.push('state=' + encodeURIComponent(opts.state));
    if (opts.q) params.push('q=' + encodeURIComponent(opts.q));
    if (params.length) url += '?' + params.join('&');
    try {
      const r = await fetch(url);
      const d = await r.json();
      if (d.properties) return d.properties.map(mapProperty);
    } catch(e) {}
    return [];
  }

  async function loadPropertyById(id) {
    try {
      const r = await fetch(GEO_API + '/properties/' + id);
      const d = await r.json();
      if (d.property) return mapProperty(d.property);
    } catch(e) {}
    return null;
  }

  async function submitEnquiry(data) {
    try {
      const r = await fetch(GEO_API + '/enquiry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      return await r.json();
    } catch(e) { return { error: e.message }; }
  }

  // ── Admin API (requires ADMIN_TOKEN) ────────────────────────────

  async function adminFetch(path, opts) {
    opts = opts || {};
    const r = await fetch(GEO_API + path, {
      method: opts.method || 'GET',
      headers: adminHeaders(),
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    return r.json();
  }

  // ── Owner Auth ──────────────────────────────────────────────────

  async function ownerRequestOTP(email) {
    try {
      const r = await fetch(GEO_API + '/owner/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      return await r.json();
    } catch(e) { return { error: e.message }; }
  }

  async function ownerVerifyOTP(email, code) {
    try {
      const r = await fetch(GEO_API + '/owner/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code })
      });
      const d = await r.json();
      if (d.success && d.token) {
        setOwnerSession({ token: d.token, owner: d.owner, loginTime: Date.now() });
      }
      return d;
    } catch(e) { return { error: e.message }; }
  }

  async function ownerFetch(path, opts) {
    opts = opts || {};
    const r = await fetch(GEO_API + path, {
      method: opts.method || 'GET',
      headers: ownerHeaders(),
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    return r.json();
  }

  // ── SSE Real-time sync ─────────────────────────────────────────
  let sseSource = null;
  const sseHandlers = {};

  function startSSE() {
    if (sseSource) return;
    try {
      sseSource = new EventSource(GEO_API + '/events');
      sseSource.onmessage = function(e) {
        try {
          const d = JSON.parse(e.data);
          if (sseHandlers['*']) sseHandlers['*'].forEach(fn => fn(d));
        } catch(ex) {}
      };
      ['property_created','property_updated','tenancy_updated','payment_updated',
       'registration_updated','new_enquiry','unit_updated','activity'].forEach(evt => {
        sseSource.addEventListener(evt, function(e) {
          try {
            const d = JSON.parse(e.data);
            if (sseHandlers[evt]) sseHandlers[evt].forEach(fn => fn(d));
          } catch(ex) {}
        });
      });
      sseSource.onerror = function() {
        // Reconnect after 5s
        if (sseSource) { sseSource.close(); sseSource = null; }
        setTimeout(startSSE, 5000);
      };
    } catch(e) {}
  }

  function onSSE(event, fn) {
    if (!sseHandlers[event]) sseHandlers[event] = [];
    sseHandlers[event].push(fn);
  }

  // ── Export ──────────────────────────────────────────────────────
  window.GeoAPI = {
    // Public
    loadPublicProperties,
    loadPropertyById,
    submitEnquiry,
    mapProperty,

    // Admin
    adminFetch,
    getAdminToken,
    setAdminToken: function(t) { localStorage.setItem(ADMIN_TOKEN_KEY, t); },

    // Owner
    ownerRequestOTP,
    ownerVerifyOTP,
    ownerFetch,
    getOwnerSession,
    setOwnerSession,
    clearOwnerSession,
    isOwnerLoggedIn: function() { return !!getOwnerSession(); },

    // SSE
    startSSE,
    onSSE,

    // Constants
    API_BASE: GEO_API
  };

  // Auto-start SSE on any page
  if (typeof window !== 'undefined') {
    window.addEventListener('load', function() {
      try { startSSE(); } catch(e) {}
    });
  }

})(window);
