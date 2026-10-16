// Builds signing options the way PKIaaS.io does, so the corpus feeds both signing paths what
// production feeds them. A copy of processOptions() in pkiaas lib/template/processTemplate.js
// (master 7218867) with the clock fixed; keep its behaviour, quirks included, in step with pkiaas.
import type { SignOptions } from './reference.ts';

export const platform = {
  ROOTFQDN: 'pkiaas.example',
  ISSUERFQDN: 'certs.pkiaas.example',
  CRLFQDN: 'crl.pkiaas.example',
  OCSPFQDN: 'ocsp.pkiaas.example',
};

export interface CustomOID {
  OID: string;
  value: string;
}

/** A template's `options` column. */
export interface TemplateOptions {
  hash?: string;
  days?: number;
  startdate?: Date;
  enddate?: Date;
  subject?: Record<string, string | string[]>;
  extensions: {
    keyUsage?: unknown;
    extendedKeyUsage?: unknown;
    basicConstraints?: unknown;
    authorityInfoAccess?: { caIssuers?: boolean | { customURL: string }; OCSP?: boolean };
    crlDistributionPoints?: boolean;
    policies?: boolean;
  };
}

export interface ProcessParams {
  ca: { publicid: string; name: string; policy_oid: string };
  csroptions: SignOptions;
  templateOID?: CustomOID | false;
  /** an admin's overrides, or a service certificate's whole options */
  requestoptions?: SignOptions;
  /** false for service certificates, which have no template */
  templateoptions: TemplateOptions | false;
  /** service certificates have none */
  template: { policy_oid?: string | null; ct_logs?: string | null } | false;
  finalcert?: boolean;
  /** the SCT list extension value, `DER:..` */
  asn1sct?: string | false;
  /** the clock: pkiaas uses the time of the request */
  now: Date;
}

const minute = 60 * 1000;
const day = 24 * 60 * minute;

function caURLs(ca: ProcessParams['ca']) {
  const name = ca.name.replace(/[^a-zA-Z0-9-_]/g, '');
  return {
    caIssuers: `http://${platform.ISSUERFQDN}/${ca.publicid}/${name}ca.crt`,
    crl: `http://${platform.CRLFQDN}/${ca.publicid}/${name}.crl`,
    cps: `https://${platform.ROOTFQDN}/${ca.publicid}/CPS`,
  };
}

export function processOptions(params: ProcessParams): SignOptions {
  const csroptions: SignOptions = structuredClone(params.csroptions);
  const extensions: Record<string, unknown> = (csroptions.extensions ??= {});
  const now = params.now.getTime();
  const templateDates = (t: TemplateOptions) =>
    t.days
      ? { startdate: new Date(now - 5 * minute), enddate: new Date(now + t.days * day) }
      : { startdate: t.startdate, enddate: t.enddate };

  // add template attribute to the cert
  if (params.templateOID) {
    extensions.customOIDs = [params.templateOID];
  }

  // prioritize request options in case overrides were provided
  const request = params.requestoptions;
  if (request) {
    if (Object.hasOwn(request, 'hash')) csroptions.hash = request.hash;
    if (request.extensions) csroptions.extensions = request.extensions;
    if (Object.hasOwn(request, 'subject')) csroptions.subject = request.subject;
    if (request.days) {
      csroptions.startdate = new Date(now);
      csroptions.enddate = new Date(now + request.days * day);
    } else if (request.startdate) {
      csroptions.startdate = request.startdate;
      csroptions.enddate = request.enddate;
    } else if (params.templateoptions) {
      Object.assign(csroptions, templateDates(params.templateoptions));
    }
  }
  const ext = csroptions.extensions;

  const t = params.templateoptions;
  const urls = caURLs(params.ca);
  let finalcert = params.finalcert ?? false;
  if (t) {
    if (t.hash) csroptions.hash = t.hash;
    if (!csroptions.startdate) Object.assign(csroptions, templateDates(t));
    ext.keyUsage = t.extensions.keyUsage;
    ext.extendedKeyUsage = t.extensions.extendedKeyUsage;
    ext.basicConstraints = t.extensions.basicConstraints;
    if (t.subject) {
      // pkiaas also replaces a false subject (`-subj /`)
      if (csroptions.subject === undefined || csroptions.subject === null || csroptions.subject === false) {
        csroptions.subject = {};
      }
      Object.assign(csroptions.subject, t.subject);
    }
    const aia = t.extensions.authorityInfoAccess;
    if (aia) {
      const value: { caIssuers?: string[]; OCSP?: string[] } = {};
      if (aia.caIssuers)
        value.caIssuers = aia.caIssuers === true ? [urls.caIssuers] : aia.caIssuers.customURL.split(',');
      if (aia.OCSP) value.OCSP = [`http://${platform.OCSPFQDN}`];
      ext.authorityInfoAccess = value;
    }
    if (t.extensions.crlDistributionPoints) ext.crlDistributionPoints = [urls.crl];
    if (t.extensions.policies) {
      ext.policies = [
        { policyIdentifier: params.ca.policy_oid, CPS: [urls.cps] },
        { policyIdentifier: params.template && params.template.policy_oid },
      ];
    }
  } else {
    const custom = ext.customOIDs as CustomOID[] | undefined;
    // OCSP signing certificates get no AIA, CDP or policies
    if (!(custom && custom.length > 0 && custom[0]?.OID === '1.3.6.1.5.5.7.48.1.5')) {
      ext.authorityInfoAccess = { caIssuers: [urls.caIssuers], OCSP: [`http://${platform.OCSPFQDN}`] };
      ext.crlDistributionPoints = [urls.crl];
      ext.policies = [{ policyIdentifier: params.ca.policy_oid, CPS: [urls.cps] }];
    }
    finalcert = true;
  }

  if ((params.template && params.template.ct_logs === null) || params.asn1sct) finalcert = true;
  const push = (oid: CustomOID) => ((ext.customOIDs ??= []) as CustomOID[]).push(oid);
  if (!finalcert) {
    // CT precertificate poison
    push({ OID: '1.3.6.1.4.1.11129.2.4.3', value: 'critical,ASN1:NULL' });
  } else if (ext.customOIDs) {
    const custom = ext.customOIDs as CustomOID[];
    const poison = custom.findIndex((o) => o.OID === '1.3.6.1.4.1.11129.2.4.3');
    if (poison >= 0) custom.splice(poison, 1);
  }
  if (params.asn1sct) push({ OID: '1.3.6.1.4.1.11129.2.4.2', value: params.asn1sct });
  return csroptions;
}
