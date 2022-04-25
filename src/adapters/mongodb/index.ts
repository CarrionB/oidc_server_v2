import { Collection, Db, MongoClient } from 'mongodb';
import snakeCase from 'lodash/snakeCase';

const grantable = new Set([
  'access_token',
  'authorization_code',
  'refresh_token',
  'device_code',
]);

let DB: Db;

class CollectionSet extends Set {
  add(name: string) {
    const nu = this.has(name);
    super.add(name);
    if (!nu) {
      DB.collection(name).createIndexes([
        ...(grantable.has(name)
          ? [{
            key: { 'payload.grantId': 1 },
          }] : []),
        ...(name === 'device_code'
          ? [{
            key: { 'payload.userCode': 1 },
            unique: true,
          }] : []),
        ...(name === 'session'
          ? [{
            key: { 'payload.uid': 1 },
            unique: true,
          }] : []),
        {
          key: { expiresAt: 1 },
          expireAfterSeconds: 0,
        },
      ]).catch(console.error); // eslint-disable-line no-console
    }
    return this
  }
}

const collections = new CollectionSet();

class MongoAdapter {
  name: string;
  constructor(name: string) {
    this.name = snakeCase(name);
    collections.add(this.name);
  }

  async upsert(_id: string, payload: any, expiresIn: any) {
    let expiresAt: any;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + (expiresIn * 1000));
    }

    await MongoAdapter.coll(this.name).updateOne(
      { _id },
      { $set: { payload, ...(expiresAt ? { expiresAt } : undefined) } },
      { upsert: true },
    );
  }

  async find(_id: string) {
    const result = await MongoAdapter.coll(this.name).find(
      { _id },
      ({ payload: 1 } as any),
    ).limit(1).next();

    if (!result) return undefined;
    return result.payload;
  }

  async findByUserCode(userCode: string) {
    const result = await MongoAdapter.coll(this.name).find(
      { 'payload.userCode': userCode },
      ({ payload: 1 } as any),
    ).limit(1).next();

    if (!result) return undefined;
    return result.payload;
  }

  async findByUid(uid: string) {
    const result = await MongoAdapter.coll(this.name).find(
      { 'payload.uid': uid },
      ({ payload: 1 } as any),
    ).limit(1).next();

    if (!result) return undefined;
    return result.payload;
  }

  async destroy(_id: any) {
    await MongoAdapter.coll(this.name).deleteOne({ _id });
  }

  async revokeByGrantId(grantId: any) {
    await MongoAdapter.coll(this.name).deleteMany({ 'payload.grantId': grantId });
  }

  async consume(_id: any) {
    await MongoAdapter.coll(this.name).findOneAndUpdate(
      { _id },
      { $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } },
    );
  }

  static coll(name: string) : Collection{
    return DB.collection(name);
  }

  static async login(email: string, password: string) {
    const result = await MongoAdapter.coll("users_data").find(
      { email: email, password: password},
    ).limit(1).next();

    if (!result) return undefined;
    return result;
  }

  static async connect() {
    console.log("process.env.MONGODB_URI => ", process.env.MONGODB_URI)
    const connection = await MongoClient.connect(process.env.MONGODB_URI as string);
    DB = connection.db(connection.options.dbName);
  }
}

export default MongoAdapter