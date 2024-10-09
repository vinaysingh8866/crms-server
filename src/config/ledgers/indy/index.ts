import _ledgers from './ledgers.json';
import type { IndyVdrPoolConfig } from '@credo-ts/indy-vdr';

// type-check the json
const ledgers: IndyVdrPoolConfig[] = _ledgers;

export default ledgers;
