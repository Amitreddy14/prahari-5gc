// Subscriber provisioning for the Prahari-5GC testbed. Runs under mongosh:
//   mongosh "mongodb://172.22.0.30/open5gs" /provision/provision.js
// Reads PRAHARI_UE_COUNT, PRAHARI_IMSI_BASE, SUBSCRIBER_K, SUBSCRIBER_OPC from the
// environment. Idempotent: re-running updates the same IMSIs instead of duplicating.
// The document layout follows the Open5GS v2.7 subscriber schema (schema_version 1).

const env = process.env;
const count = parseInt(env.PRAHARI_UE_COUNT || "10", 10);
const imsiBase = env.PRAHARI_IMSI_BASE || "001010000000001";
const k = env.SUBSCRIBER_K || "";
const opc = env.SUBSCRIBER_OPC || "";

function fail(msg) {
  print(`provision: ERROR ${msg}`);
  quit(64);
}

if (!/^[0-9A-Fa-f]{32}$/.test(k)) fail("SUBSCRIBER_K must be 32 hex characters");
if (!/^[0-9A-Fa-f]{32}$/.test(opc)) fail("SUBSCRIBER_OPC must be 32 hex characters");
if (!/^[0-9]{15}$/.test(imsiBase)) fail("PRAHARI_IMSI_BASE must be 15 digits");
if (!Number.isInteger(count) || count < 1 || count > 1000) fail("PRAHARI_UE_COUNT must be 1..1000");

// 15-digit IMSIs exceed 2^53, so count up with BigInt to stay exact.
function imsiAt(i) {
  return (BigInt(imsiBase) + BigInt(i)).toString().padStart(15, "0");
}

// Every IMSI must stay inside the testbed PLMN (MCC 001, MNC 01).
const plmnPrefix = imsiBase.slice(0, 5);
if (imsiAt(count - 1).slice(0, 5) !== plmnPrefix) {
  fail(`IMSI range overflows PLMN ${plmnPrefix}: lower PRAHARI_IMSI_BASE or PRAHARI_UE_COUNT`);
}

const ambr = {
  downlink: { value: NumberInt(1000000000), unit: NumberInt(0) },
  uplink: { value: NumberInt(1000000000), unit: NumberInt(0) },
};

function subscriber(imsi) {
  return {
    schema_version: NumberInt(1),
    imsi: imsi,
    msisdn: [],
    imeisv: [],
    mme_host: [],
    mm_realm: [],
    purge_flag: [],
    slice: [
      {
        sst: NumberInt(1),
        default_indicator: true,
        session: [
          {
            name: "internet",
            type: NumberInt(3), // IPv4v6
            qos: {
              index: NumberInt(9),
              arp: {
                priority_level: NumberInt(8),
                pre_emption_capability: NumberInt(1),
                pre_emption_vulnerability: NumberInt(2),
              },
            },
            ambr: ambr,
            pcc_rule: [],
            _id: new ObjectId(),
          },
        ],
        _id: new ObjectId(),
      },
    ],
    security: { k: k.toUpperCase(), op: null, opc: opc.toUpperCase(), amf: "8000" },
    ambr: ambr,
    access_restriction_data: 32,
    network_access_mode: 0,
    subscriber_status: 0,
    operator_determined_barring: 0,
    subscribed_rau_tau_timer: 12,
    __v: 0,
  };
}

db.subscribers.createIndex({ imsi: 1 }, { unique: true });

let created = 0;
let updated = 0;
for (let i = 0; i < count; i++) {
  const imsi = imsiAt(i);
  const res = db.subscribers.replaceOne({ imsi: imsi }, subscriber(imsi), { upsert: true });
  if (res.upsertedCount === 1) created++;
  else updated++;
}

print(
  `provision: ${count} subscriber(s) imsi-${imsiAt(0)} .. imsi-${imsiAt(count - 1)} ` +
    `(created ${created}, updated ${updated}); total in db: ${db.subscribers.countDocuments({})}`
);
