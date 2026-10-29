import { generateKeyPair, importSealingKey, KEYSET_FORMAT, sealRecord, type KeySet, type RecordBody, type SealformRecord } from '../src/core/index.ts';

export async function makeKey(kid = 'test-key') {
  const { privateFile, publicEntry } = await generateKeyPair(kid);
  const key = await importSealingKey(privateFile);
  const keyset: KeySet = { format: KEYSET_FORMAT, keys: [publicEntry] };
  return { key, keyset, privateFile, publicEntry };
}

export function body(seq: number, prevHash: string, overrides: Partial<RecordBody> = {}): RecordBody {
  return {
    format: 'sealform/record@1',
    id: `sf_TEST${seq}`,
    document: { id: 'example-agreement', version: 'EXAMPLE-1', lang: 'en', sha256: 'a'.repeat(64) },
    disclosure: { id: 'esign', version: 'esign-1', lang: 'en', sha256: 'b'.repeat(64) },
    fields: { legalName: 'Ada Example', email: 'ada@example.com', country: 'DE' },
    consent: { esign: true, acceptVersion: true },
    signature: { typedName: 'Ada Example', vector: [[{ x: 1, y: 2, time: 3 }]], pngSha256: 'c'.repeat(64) },
    assurance: { level: 'ses', checks: [{ kind: 'email-receipt', status: 'queued' }] },
    server: {
      receivedAt: '2026-11-02T18:04:11.532Z',
      sessionOpenedAt: '2026-11-02T18:01:00.000Z',
      ip: '203.0.113.7',
      userAgent: 'test-agent',
      acceptLanguage: 'de-DE,de;q=0.9',
    },
    client: { timeZone: 'Europe/Berlin', screen: '390x844' },
    chain: { seq, prevHash },
    ...overrides,
  };
}

export async function chainOf(count: number, key: Awaited<ReturnType<typeof makeKey>>['key']): Promise<SealformRecord[]> {
  const records: SealformRecord[] = [];
  let prev = '0'.repeat(64);
  for (let seq = 0; seq < count; seq++) {
    const record = await sealRecord(body(seq, prev), key);
    records.push(record);
    prev = record.hash;
  }
  return records;
}
