import { createConnection, EntitySchema } from 'typeorm';

// Define each entity schema required by oidc-provider

// Client Entity
const ClientSchema = new EntitySchema({
  name: 'Client',
  tableName: 'clients',
  columns: {
    client_id: { primary: true, type: 'varchar' },
    client_secret: { type: 'varchar' },
    redirect_uris: { type: 'simple-json' },
    grant_types: { type: 'simple-json' },
    response_types: { type: 'simple-json' },
    token_endpoint_auth_method: { type: 'varchar' },
    require_pkce: { type: 'boolean' },
  },
});

// Session Entity
const SessionSchema = new EntitySchema({
  name: 'Session',
  tableName: 'sessions',
  columns: {
    uid: { primary: true, type: 'varchar' },
    jti: { type: 'varchar' },
    grantId: { type: 'varchar' },
    // Additional session properties
  },
});

// Grant Entity
const GrantSchema = new EntitySchema({
  name: 'Grant',
  tableName: 'grants',
  columns: {
    id: { primary: true, type: 'varchar' },
    accountId: { type: 'varchar' },
    claims: { type: 'simple-json' },
  },
});

// Code Entity
const CodeSchema = new EntitySchema({
  name: 'Code',
  tableName: 'codes',
  columns: {
    code: { primary: true, type: 'varchar' },
    client_id: { type: 'varchar' },
    redirect_uri: { type: 'varchar' },
    response_type: { type: 'varchar' },
    scope: { type: 'varchar' },
    state: { type: 'varchar' },
    code_challenge: { type: 'varchar' },
    code_challenge_method: { type: 'varchar' },
  },
});

// Access Token Entity
const AccessTokenSchema = new EntitySchema({
  name: 'AccessToken',
  tableName: 'access_tokens',
  columns: {
    access_token: { primary: true, type: 'varchar' },
    client_id: { type: 'varchar' },
    account_id: { type: 'varchar' },
    scope: { type: 'varchar' },
    expires_at: { type: 'bigint' },
  },
});

// Refresh Token Entity
const RefreshTokenSchema = new EntitySchema({
  name: 'RefreshToken',
  tableName: 'refresh_tokens',
  columns: {
    refresh_token: { primary: true, type: 'varchar' },
    client_id: { type: 'varchar' },
    account_id: { type: 'varchar' },
    scope: { type: 'varchar' },
    expires_at: { type: 'bigint' },
  },
});

// Device Code Entity
const DeviceCodeSchema = new EntitySchema({
  name: 'DeviceCode',
  tableName: 'device_codes',
  columns: {
    device_code: { primary: true, type: 'varchar' },
    user_code: { type: 'varchar' },
    client_id: { type: 'varchar' },
    scope: { type: 'varchar' },
    expires_at: { type: 'bigint' },
  },
});

// Interaction Entity
const InteractionSchema = new EntitySchema({
  name: 'Interaction',
  tableName: 'interactions',
  columns: {
    uid: { primary: true, type: 'varchar' },
    jti: { type: 'varchar' },
    grantId: { type: 'varchar', nullable: true },
    session: { type: 'simple-json', nullable: true },
    params: { type: 'simple-json', nullable: true },
  },
});

// Initialize TypeORM connection and adapter
let connection;

export const initializeAdapter = async () => {
  connection = await createConnection({
    type: 'sqlite',
    database: 'oidc.sqlite',
    synchronize: true, // Automatically sync schema; disable in production
    logging: false,
    entities: [
      ClientSchema,
      SessionSchema,
      GrantSchema,
      CodeSchema,
      AccessTokenSchema,
      RefreshTokenSchema,
      DeviceCodeSchema,
      InteractionSchema, // Add InteractionSchema to TypeORM entities
    ],
  });
};

// Factory function to create adapters for each model
export const typeormAdapter = (model) => {
  if (!connection) {
    throw new Error('TypeORM connection not established. Call initializeAdapter() first.');
  }

  const repository = connection.getRepository(model);

  return {
    async upsert(id, payload, expiresIn) {
      let entity;
      if (model === 'Client') {
        entity = await repository.findOne({ client_id: id }) || repository.create({ client_id: id });
      } else if (model === 'Session') {
        entity = await repository.findOne({ uid: id }) || repository.create({ uid: id });
      } else if (model === 'Grant') {
        entity = await repository.findOne(id) || repository.create({ id });
      } else if (model === 'Code') {
        entity = await repository.findOne({ code: id }) || repository.create({ code: id });
      } else if (model === 'AccessToken') {
        entity = await repository.findOne({ access_token: id }) || repository.create({ access_token: id });
      } else if (model === 'RefreshToken') {
        entity = await repository.findOne({ refresh_token: id }) || repository.create({ refresh_token: id });
      } else if (model === 'DeviceCode') {
        entity = await repository.findOne({ device_code: id }) || repository.create({ device_code: id });
      } else if (model === 'Interaction') {
        entity = await repository.findOne({ uid: id }) || repository.create({ uid: id });
      } else {
        throw new Error(`Unknown model: ${model}`);
      }
      repository.merge(entity, payload);
      await repository.save(entity);
      return entity;
    },

    async find(id) {
      if (model === 'Client') {
        return repository.findOne({ client_id: id });
      } else if (model === 'Session') {
        return repository.findOne({ uid: id });
      } else if (model === 'Grant') {
        return repository.findOne(id);
      } else if (model === 'Code') {
        return repository.findOne({ code: id });
      } else if (model === 'AccessToken') {
        return repository.findOne({ access_token: id });
      } else if (model === 'RefreshToken') {
        return repository.findOne({ refresh_token: id });
      } else if (model === 'DeviceCode') {
        return repository.findOne({ device_code: id });
      } else if (model === 'Interaction') {
        return repository.findOne({ uid: id });
      } else {
        throw new Error(`Unknown model: ${model}`);
      }
    },

    async findByUid(uid) {
      if (model === 'Session' || model === 'Interaction') {
        return repository.findOne({ uid });
      }
      return null;
    },

    async findByUserCode(userCode) {
      if (model === 'DeviceCode') {
        return repository.findOne({ user_code: userCode });
      }
      return null;
    },

    async findByUidAndUserCode(uid, userCode) {
      if (model === 'DeviceCode') {
        return repository.findOne({ device_code: uid, user_code: userCode });
      }
      return null;
    },

    async destroy(id) {
      if (model === 'Interaction' || model === 'Session' || model === 'Code' || model === 'Grant' || model === 'AccessToken' || model === 'RefreshToken') {
        await repository.delete({ uid: id });
      }
    },

    async consume(id) {
      if (model === 'Code') {
        await repository.delete({ code: id });
      }
    },

    async destroyByGrantId(grantId) {
      if (model === 'Grant') {
        await repository.delete(grantId);
      }
    },

    async revokeByGrantId(grantId) {
      if (model === 'AccessToken' || model === 'RefreshToken') {
        await repository.delete({ grantId });
      }
    },
  };
};
