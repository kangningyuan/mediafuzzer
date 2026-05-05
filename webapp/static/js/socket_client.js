/**
 * MediaFuzzer SocketIO Client Helpers
 * Provides reconnection logic and event dispatching.
 */

// Socket is initialized in base.html template as: const socket = io();

// Reconnection handling is built into Socket.IO client by default.
// These helpers provide convenience functions for common patterns.

function emitSafe(event, data) {
  if (typeof socket !== 'undefined' && socket.connected) {
    socket.emit(event, data);
  } else {
    console.warn('Socket not connected, cannot emit:', event);
  }
}

function apiPost(url, data, onSuccess, onError) {
  fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data || {})
  })
  .then(r => {
    if (!r.ok && onError) {
      return r.json().then(err => onError(err)).catch(() => onError({error: 'Request failed'}));
    }
    return r.json();
  })
  .then(data => {
    if (onSuccess) onSuccess(data);
  })
  .catch(err => {
    console.error('API error:', err);
    if (onError) onError(err);
  });
}

function apiGet(url, onSuccess, onError) {
  fetch(url)
  .then(r => r.json())
  .then(data => {
    if (onSuccess) onSuccess(data);
  })
  .catch(err => {
    console.error('API error:', err);
    if (onError) onError(err);
  });
}
