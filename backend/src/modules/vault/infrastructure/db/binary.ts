/**
 * Buffer <-> MongoDB Binary conversion helpers.
 *
 * The vault ports carry binary fields as `Buffer` (matching Node's
 * `node:crypto` types). The Mongo driver returns `Binary` instances
 * from BSON deserialization; we want `Buffer` so the rest of the
 * application doesn't have to know about the driver.
 *
 * Both `Buffer` and `Binary` extend `Uint8Array`, so the round-trip
 * is allocation-free — we just construct a Buffer view over the
 * existing bytes. The reverse direction (Buffer -> Binary) goes
 * through BSON serialization automatically when the driver writes
 * a document, so we never need to wrap a Buffer manually.
 */
import { Binary } from 'mongodb';

/** Coerce a BSON Binary (or already-Buffer) to a fresh Buffer. */
export function toBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Binary) {
    // `Binary` exposes its underlying allocation as `.buffer` and the
    // offset / length of the data as `.position` / `.length()` (a
    // method, not a property — see mongodb's BSON Binary class). Copy
    // the byte range into a fresh Buffer so callers can mutate / zero
    // the result without aliasing other rows.
    const buf = value.buffer;
    const start = value.position;
    const end = start + value.length();
    return Buffer.from(buf.buffer ?? buf, start, end - start);
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  throw new TypeError(
    `[vault] expected Buffer/Binary/Uint8Array, got ${typeof value}`,
  );
}
