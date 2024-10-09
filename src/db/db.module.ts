import { Module } from '@nestjs/common';
import { Pool } from 'pg';
import { PG_CONNECTION } from '../constants';
import 'dotenv/config';

// Database configuration
const dbProvider = {
  provide: PG_CONNECTION,
  useValue: new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: parseInt(process.env.DB_PORT || ''),
  }),
};

@Module({
  providers: [dbProvider],
  exports: [dbProvider],
})
export class DbModule {}
