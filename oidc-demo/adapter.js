// adapter.js
import QuickLRU from 'quick-lru';

const storage = new QuickLRU({ maxSize: 1000 });

function grantKeyFor(id) {
  return `grant:${id}`;
}

function sessionUidKeyFor(id) {
  return `sessionUid:${id}`;
}

function userCodeKeyFor(userCode) {
  return `userCode:${userCode}`;
}

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

class MemoryAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return `${this.name}:${id}`;
  }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    storage.set(key, payload, expiresIn * 1000);

    if (grantable.has(this.name) && payload.grantId) {
      const grantKey = grantKeyFor(payload.grantId);
      const grant = storage.get(grantKey);
      if (!grant) {
        storage.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
    }

    if (this.name === 'Session') {
      storage.set(sessionUidKeyFor(payload.uid), id, expiresIn * 1000);
    }

    if (payload.userCode) {
      storage.set(userCodeKeyFor(payload.userCode), id, expiresIn * 1000);
    }
  }

  async find(id) {
    const data = storage.get(this.key(id));
    if (!data) return undefined;
    return data;
  }

  async findByUserCode(userCode) {
    const id = storage.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  async findByUid(uid) {
    const id = storage.get(sessionUidKeyFor(uid));
    return this.find(id);
  }

  async destroy(id) {
    const key = this.key(id);
    storage.delete(key);
  }

  async revokeByGrantId(grantId) {
    const grantKey = grantKeyFor(grantId);
    const grant = storage.get(grantKey);
    if (grant) {
      grant.forEach((token) => storage.delete(token));
      storage.delete(grantKey);
    }
  }

  async consume(id) {
    const key = this.key(id);
    const data = storage.get(key);
    if (data) {
      data.consumed = Math.floor(Date.now() / 1000);
      storage.set(key, data);
    }
  }
}

export default MemoryAdapter;
