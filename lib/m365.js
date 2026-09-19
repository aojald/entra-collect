/**
 * M365 collaboration / mail security checks (SharePoint, Teams, anti-spam, forwarding).
 * Best-effort via Graph + optional Exchange Admin API token from portal session.
 */
const SHARING_LABELS = {
  disabled: "Disabled (most restrictive)",
  existingExternalUserSharingOnly: "Existing external users only",
  externalUserSharingOnly: "New and existing guests",
  externalUserAndGuestSharing: "Anyone (anonymous links) — HIGH RISK",
};

function sharingLabel(cap) {
  if (!cap) return "unknown";
  return SHARING_LABELS[cap] || cap;
}

const { soft, STATUS } = require("./io");

/**
 * @param {object} graph - createGraph(pool)
 * @param {object} pool - TokenPool (may hold Exchange tokens)
 * @param {object} io
 * @param {object} findings
 * @param {object} summary
 */
async function collectM365CollabAndMail(graph, pool, io, findings, summary, opts = {}) {
  const schema = opts.schema || {
    canHunt: false,
    has: () => false,
    huntApiStatus: "unknown",
  };
  console.log("── SharePoint / OneDrive tenant sharing");
  const spo = await soft(
    "sharePointSettings",
    () => graph.get(`${graph.GRAPH}/admin/sharepoint/settings`),
    io
  );
  if (spo) {
    io.saveJson("15_sharepoint_settings.json", spo);
    summary.spoSharingCapability = spo.sharingCapability;
    summary.spoSharingLabel = sharingLabel(spo.sharingCapability);
    summary.spoResharingByExternal = spo.isResharingByExternalUsersEnabled;
    summary.spoLegacyAuth = spo.isLegacyAuthProtocolsEnabled;
    summary.spoSitePagesEnabled = spo.isSitePagesEnabled;
    summary.spoIdleSessionSignOut = spo.isIdleSessionSignOutEnabled;
    summary.spoDefaultLinkPermission = spo.defaultLinkPermission;
    summary.spoDefaultSharingLinkType = spo.defaultSharingLinkType;
    summary.spoFileRequest = spo.isFileRequestEnabled;

    io.saveCsv("15_SharePoint_Tenant_Sharing.csv", [
      {
        SharingCapability: spo.sharingCapability,
        SharingLabel: sharingLabel(spo.sharingCapability),
        ResharingByExternalUsers: spo.isResharingByExternalUsersEnabled,
        LegacyAuthProtocolsEnabled: spo.isLegacyAuthProtocolsEnabled,
        DefaultSharingLinkType: spo.defaultSharingLinkType,
        DefaultLinkPermission: spo.defaultLinkPermission,
        IdleSessionSignOut: spo.isIdleSessionSignOutEnabled,
        FileRequestEnabled: spo.isFileRequestEnabled,
        SitePagesEnabled: spo.isSitePagesEnabled,
        ImageTaggingOption: spo.imageTaggingOption,
      },
    ]);

    if (
      spo.sharingCapability === "externalUserAndGuestSharing" ||
      String(spo.sharingCapability).toLowerCase().includes("anyone")
    ) {
      findings.push({
        Severity: "High",
        Area: "SharePoint",
        Detail:
          "Tenant allows Anyone/anonymous sharing (externalUserAndGuestSharing) — oversharing risk",
      });
    } else if (spo.sharingCapability === "externalUserSharingOnly") {
      findings.push({
        Severity: "Medium",
        Area: "SharePoint",
        Detail: "Tenant allows inviting new external users to SharePoint/OneDrive",
      });
    } else {
      findings.push({
        Severity: "Info",
        Area: "SharePoint",
        Detail: `SharingCapability=${spo.sharingCapability} (${sharingLabel(spo.sharingCapability)})`,
      });
    }
    if (spo.isLegacyAuthProtocolsEnabled === true) {
      findings.push({
        Severity: "Medium",
        Area: "SharePoint",
        Detail: "Legacy auth protocols enabled on SharePoint",
      });
    }
    if (spo.isResharingByExternalUsersEnabled === true) {
      findings.push({
        Severity: "Medium",
        Area: "SharePoint",
        Detail: "External users may reshare content",
      });
    }
  }

  // Sample sites (oversharing signals: public sites, high sharing)
  console.log("── SharePoint sites sample (oversharing signals)");
  const sites = await soft(
    "sharePointSites",
    () =>
      graph.getAll(
        `${graph.GRAPH}/sites?$select=id,displayName,webUrl,siteCollection,isPersonalSite,createdDateTime&$top=100`
      ),
    io
  );
  if (sites && Array.isArray(sites)) {
    const siteRows = sites.slice(0, 100).map((s) => ({
      DisplayName: s.displayName,
      WebUrl: s.webUrl,
      IsPersonalSite: s.isPersonalSite,
      Created: s.createdDateTime,
      Hostname: s.siteCollection && s.siteCollection.hostname,
    }));
    io.saveCsv("15_SharePoint_Sites_Sample.csv", siteRows);
    summary.spoSitesSampled = siteRows.length;
  }

  console.log("── Cross-tenant / external identities");
  const ctaDefault = await soft(
    "crossTenantAccessDefault",
    () =>
      graph.get(`${graph.GRAPH}/policies/crossTenantAccessPolicy/default`),
    io
  );
  /** Flatten one cross-tenant access setting (default or partner) into a trust row. */
  const trustRow = (label, tenantId, c) => {
    const acc = (x) => (x && x.usersAndGroups && x.usersAndGroups.accessType) || "";
    const apps = (x) => (x && x.applications && x.applications.accessType) || "";
    const trust = c.inboundTrust || {};
    const auto = c.automaticUserConsentSettings || {};
    return {
      Scope: label,
      TenantId: tenantId || "",
      B2BCollabInboundUsers: acc(c.b2bCollaborationInbound),
      B2BCollabInboundApps: apps(c.b2bCollaborationInbound),
      B2BCollabOutboundUsers: acc(c.b2bCollaborationOutbound),
      B2BDirectConnectInbound: acc(c.b2bDirectConnectInbound),
      B2BDirectConnectOutbound: acc(c.b2bDirectConnectOutbound),
      TrustMfa: trust.isMfaAccepted,
      TrustCompliantDevice: trust.isCompliantDeviceAccepted,
      TrustHybridJoined: trust.isHybridAzureADJoinedDeviceAccepted,
      AutoConsentInbound: auto.inboundAllowed,
      AutoConsentOutbound: auto.outboundAllowed,
      IsServiceProvider: c.isServiceProvider,
    };
  };
  const trustRows = [];

  if (ctaDefault) {
    io.saveJson("15_cross_tenant_access_default.json", ctaDefault);
    summary.ctaB2bCollaborationInbound =
      ctaDefault.b2bCollaborationInbound &&
      ctaDefault.b2bCollaborationInbound.usersAndGroups &&
      ctaDefault.b2bCollaborationInbound.usersAndGroups.accessType;
    summary.ctaB2bCollaborationOutbound =
      ctaDefault.b2bCollaborationOutbound &&
      ctaDefault.b2bCollaborationOutbound.usersAndGroups &&
      ctaDefault.b2bCollaborationOutbound.usersAndGroups.accessType;
    const def = trustRow("default", "", ctaDefault);
    trustRows.push(def);
    summary.ctaDefaultTrustMfa = def.TrustMfa;
    summary.ctaDefaultTrustCompliantDevice = def.TrustCompliantDevice;
    summary.ctaDefaultDirectConnectInbound = def.B2BDirectConnectInbound;
    findings.push({
      Severity: "Info",
      Area: "ExternalIdentities",
      Detail: `Cross-tenant default B2B inbound=${summary.ctaB2bCollaborationInbound}; outbound=${summary.ctaB2bCollaborationOutbound}; direct connect inbound=${def.B2BDirectConnectInbound || "n/a"}`,
    });
    // Trusting every external tenant's MFA / device claims tenant-wide means a
    // guest's home-tenant MFA (whatever it is) satisfies this tenant's CA.
    if (def.TrustMfa === true || def.TrustCompliantDevice === true || def.TrustHybridJoined === true) {
      findings.push({
        Severity: "Medium",
        Area: "ExternalIdentities",
        Detail:
          `Default inbound trust accepts external claims from *every* tenant (isMfaAccepted=${def.TrustMfa}, isCompliantDeviceAccepted=${def.TrustCompliantDevice}, isHybridAzureADJoinedDeviceAccepted=${def.TrustHybridJoined}) — guest MFA / device CA is satisfied by the partner's own policy. Scope trust to named partner tenants — 15_CrossTenant_Trust.csv`,
      });
    }
    if (/allowed/i.test(String(def.B2BDirectConnectInbound))) {
      findings.push({
        Severity: "Medium",
        Area: "ExternalIdentities",
        Detail:
          "B2B direct connect is allowed inbound by default for all tenants — any external organisation can be invited into shared Teams channels without a guest object to review. Restrict to named partners — 15_CrossTenant_Trust.csv",
      });
    }
  }
  const ctaPartners = await soft(
    "crossTenantAccessPartners",
    () =>
      graph.getAll(`${graph.GRAPH}/policies/crossTenantAccessPolicy/partners`),
    io
  );
  if (ctaPartners) {
    io.saveJson("15_cross_tenant_access_partners.json", ctaPartners);
    summary.ctaPartnerCount = ctaPartners.length;
    io.saveCsv(
      "15_CrossTenant_Partners.csv",
      ctaPartners.map((p) => ({
        TenantId: p.tenantId,
        DisplayName: p.displayName,
        IsServiceProvider: p.isServiceProvider,
        TrustMfa: p.inboundTrust ? p.inboundTrust.isMfaAccepted : "",
        TrustCompliantDevice: p.inboundTrust ? p.inboundTrust.isCompliantDeviceAccepted : "",
        AutoConsentInbound: p.automaticUserConsentSettings
          ? p.automaticUserConsentSettings.inboundAllowed
          : "",
      }))
    );
    for (const p of ctaPartners) trustRows.push(trustRow("partner", p.tenantId, p));
    const partnersTrusting = ctaPartners.filter(
      (p) => p.inboundTrust && (p.inboundTrust.isMfaAccepted || p.inboundTrust.isCompliantDeviceAccepted)
    );
    const autoRedeem = ctaPartners.filter(
      (p) => p.automaticUserConsentSettings && p.automaticUserConsentSettings.inboundAllowed
    );
    summary.ctaPartnersTrustingMfa = partnersTrusting.length;
    if (partnersTrusting.length || autoRedeem.length) {
      findings.push({
        Severity: "Info",
        Area: "ExternalIdentities",
        Detail:
          `${partnersTrusting.length} partner tenant(s) trusted for MFA / device claims` +
          (autoRedeem.length ? `; ${autoRedeem.length} with automatic invitation redemption` : "") +
          ` — verify each is a contracted partner (${partnersTrusting.map((p) => p.tenantId).slice(0, 4).join(", ")}) — 15_CrossTenant_Trust.csv`,
      });
    }
  }
  if (trustRows.length) io.saveCsv("15_CrossTenant_Trust.csv", trustRows);

  // CSP contracts + GDAP / delegated admin relationships (admin.cloud.microsoft partners).
  // Often requires Global Admin / privileged partner roles — soft-fail when denied.
  console.log("── Partner / GDAP relationships");
  const contracts = await soft(
    "partnerContracts",
    () => graph.getAll(`${graph.GRAPH}/contracts`),
    io
  );
  if (Array.isArray(contracts)) {
    io.saveJson("15_partner_contracts.json", contracts);
    io.saveCsv(
      "15_Partner_Contracts.csv",
      contracts.map((c) => ({
        Id: c.id,
        DisplayName: c.displayName,
        ContractType: c.contractType || "",
        CustomerId: c.customerId || "",
        DefaultDomainName: c.defaultDomainName || "",
      }))
    );
    summary.partnerContractCount = contracts.length;
    if (contracts.length) {
      findings.push({
        Severity: "Info",
        Area: "Partners",
        Detail: `${contracts.length} CSP/partner contract(s) — 15_Partner_Contracts.csv`,
      });
    }
  }

  const gdap = await soft(
    "delegatedAdminRelationships",
    async () => {
      try {
        return await graph.getAll(
          `${graph.GRAPH_BETA}/tenantRelationships/delegatedAdminRelationships`
        );
      } catch (e) {
        // Alternate path used on some tenants.
        if (e && e.status === 404) {
          return graph.getAll(
            `${graph.GRAPH}/tenantRelationships/delegatedAdminRelationships`
          );
        }
        throw e;
      }
    },
    io
  );
  if (Array.isArray(gdap)) {
    io.saveJson("15_delegated_admin_relationships.json", gdap);
    io.saveCsv(
      "15_GDAP_Relationships.csv",
      gdap.map((r) => ({
        Id: r.id,
        DisplayName: r.displayName,
        Status: r.status || "",
        Duration: r.duration || "",
        PartnerTenantId:
          (r.partner && (r.partner.tenantId || r.partner.displayName)) || "",
        CustomerTenantId:
          (r.customer && (r.customer.tenantId || r.customer.displayName)) || "",
        AccessDetails: JSON.stringify(r.accessDetails || {}).slice(0, 300),
        Activated: r.activatedDateTime || "",
        End: r.endDateTime || "",
      }))
    );
    summary.gdapRelationshipCount = gdap.length;
    const active = gdap.filter((r) => /active/i.test(String(r.status || "")));
    findings.push({
      Severity: active.length ? "Medium" : "Info",
      Area: "Partners",
      Detail: `${gdap.length} GDAP/delegated-admin relationship(s) (${active.length} active) — 15_GDAP_Relationships.csv`,
    });
  } else {
    findings.push({
      Severity: "Info",
      Area: "Partners",
      Detail:
        "GDAP / delegated-admin relationships not readable with this session (admin.cloud.microsoft partners often requires Global Administrator). Cross-tenant access partners still in 15_CrossTenant_Partners.csv.",
    });
  }

  console.log("── Teams / group guest settings");
  // Unified group guest settings via groupSettings (Graph v1.0; /settings is invalid)
  const dirSettings = await soft(
    "directorySettingsTeams",
    async () => {
      try {
        return await graph.getAll(`${graph.GRAPH}/groupSettings`);
      } catch (e) {
        if (e && e.status === 404) {
          return graph.getAll(`${graph.GRAPH_BETA}/groupSettings`);
        }
        throw e;
      }
    },
    io
  );
  if (dirSettings) {
    const guestSetting = dirSettings.find(
      (s) =>
        (s.displayName || "").includes("Group.Unified") ||
        (s.templateId || "") === "62375ab9-6b52-47ed-826b-58e47e0e304b"
    );
    if (guestSetting) {
      io.saveJson("16_teams_group_unified_settings.json", guestSetting);
      const map = Object.fromEntries(
        (guestSetting.values || []).map((v) => [v.name, v.value])
      );
      summary.groupsAllowGuestsToBecomeOwner = map.AllowGuestsToBeGroupOwner;
      summary.groupsAllowGuestsToAccessGroups = map.AllowGuestsToAccessGroups;
      summary.groupsAllowToAddGuests = map.AllowToAddGuests;
      summary.groupsGuestUsageGuidelinesUrl = map.GuestUsageGuidelinesUrl;
      io.saveCsv("16_Teams_Group_Guest_Settings.csv", [map]);
      if (String(map.AllowToAddGuests).toLowerCase() === "true") {
        findings.push({
          Severity: "Medium",
          Area: "Teams",
          Detail: "Groups/Teams AllowToAddGuests=true (users may add guests if not blocked elsewhere)",
        });
      }
    }
  }

  const teamsAppSettings = await soft(
    "teamsAppSettings",
    () => graph.get(`${graph.GRAPH_BETA}/teamwork/teamsAppSettings`),
    io
  );
  if (teamsAppSettings) {
    io.saveJson("16_teams_app_settings.json", teamsAppSettings);
    summary.teamsUserRequestingAppPermission =
      teamsAppSettings.isUserRequestingAccessToAppAllowed;
  }

  // Sample a few teams for guest settings
  const teams = await soft(
    "teamsList",
    () =>
      graph.getAll(
        `${graph.GRAPH}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName,visibility,mailEnabled&$top=50`
      ),
    io
  );
  if (teams && teams.length) {
    const teamRows = [];
    for (const t of teams.slice(0, 25)) {
      let guestSettings = null;
      try {
        guestSettings = await graph.get(
          `${graph.GRAPH}/teams/${t.id}?$select=guestSettings,memberSettings,messagingSettings,funSettings,discoverySettings`
        );
      } catch {
        /* skip */
      }
      teamRows.push({
        DisplayName: t.displayName,
        Visibility: t.visibility,
        AllowCreateUpdateChannels:
          guestSettings &&
          guestSettings.guestSettings &&
          guestSettings.guestSettings.allowCreateUpdateChannels,
        AllowDeleteChannels:
          guestSettings &&
          guestSettings.guestSettings &&
          guestSettings.guestSettings.allowDeleteChannels,
      });
    }
    io.saveCsv("16_Teams_Sample_GuestSettings.csv", teamRows);
    summary.teamsSampled = teamRows.length;
  }

  // ── Anti-spam / Defender for Office (schema-aware) ───────────────────
  console.log("── Email anti-spam / Defender for Office (schema-aware)");
  if (schema.canHunt && schema.has("EmailEvents")) {
    const spamHunt = await soft(
      "antiSpamHuntingHint",
      () =>
        graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
          Query: `
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| summarize Count=count() by DeliveryLocation, ThreatTypes
| top 20 by Count
`.trim(),
        }),
      io
    );
    if (spamHunt && spamHunt.results) {
      io.saveCsv(
        "17_Email_Delivery_7d_Sample.csv",
        spamHunt.results.map((r) => ({
          DeliveryLocation: r.DeliveryLocation,
          ThreatTypes: r.ThreatTypes,
          Count: r.Count,
        }))
      );
      io.saveJson("17_email_delivery_hunting_raw.json", spamHunt);
    }
  } else {
    console.log(
      `  · Skip EmailEvents hunt (${!schema.canHunt ? schema.huntApiStatus || "no hunt API" : "EmailEvents missing"})`
    );
  }

  // Preset / configuration state via security portal Graph is limited; document expected checks
  const antiSpamChecklist = [
    {
      Control: "Preset security policies (Standard/Strict)",
      Why: "Baseline anti-phish, anti-spam, anti-malware, Safe Links/Attachments",
      Where: "security.microsoft.com → Email & collaboration → Policies & rules → Preset security policies",
      GraphAutomatable: "Partial — confirm in portal / EXO PowerShell",
    },
    {
      Control: "Anti-spam inbound policy (SCL, bulk threshold, quarantine)",
      Why: "Blocks spam / bulk; quarantine vs Junk",
      Where: "security.microsoft.com → Anti-spam policies",
      GraphAutomatable: "No (EXO Get-HostedContentFilterPolicy)",
    },
    {
      Control: "Anti-phishing (impersonation, mailbox intelligence, spoof)",
      Why: "BEC / spoofing protection",
      Where: "security.microsoft.com → Anti-phishing policies",
      GraphAutomatable: "No (EXO Get-AntiPhishPolicy)",
    },
    {
      Control: "Safe Links / Safe Attachments (Defender for Office 365)",
      Why: "Zero-day URL/file detonation",
      Where: "security.microsoft.com → Safe Links / Safe Attachments",
      GraphAutomatable: "Limited",
    },
    {
      Control: "Outbound spam — AutoForwardingMode",
      Why: "Block automatic forwarding to external domains",
      Where: "Anti-spam outbound policy → Automatic forwarding",
      GraphAutomatable: "Try Exchange Admin API below",
    },
    {
      Control: "DMARC/DKIM/SPF",
      Why: "Domain spoofing resistance",
      Where: "Defender → Email authentication settings + DNS",
      GraphAutomatable: "DKIM via EXO; SPF/DMARC via DNS",
    },
  ];
  io.saveCsv("17_AntiSpam_Manual_Checklist.csv", antiSpamChecklist);
  findings.push({
    Severity: "Info",
    Area: "AntiSpam",
    Detail:
      "EOP/MDO policy objects are mostly Exchange-only — see 17_AntiSpam_Manual_Checklist.csv; hunting sample in 17_Email_Delivery_7d_Sample.csv if permitted",
  });

  // ── Mailbox external forwarding ───────────────────────────────────────
  console.log("── Mailbox external forwarding / redirects");
  const tenantId =
    (pool.best && pool.best() && pool.best().payload && pool.best().payload.tid) ||
    (pool.list()[0] && pool.list()[0].payload.tid);

  // Try Exchange Admin API if we captured an Outlook token
  const exoToken = pool.bestForAudience && pool.bestForAudience("outlook.office365.com");
  let exoForwardPolicy = null;
  if (exoToken && tenantId) {
    exoForwardPolicy = await soft(
      "exoOutboundSpamOrRemoteDomain",
      async () => {
        // Exchange Admin REST varies; try InvokeCommand style used by EAC
        const url = `https://outlook.office365.com/adminapi/beta/${tenantId}/InvokeCommand`;
        return fetchJsonResilient(url, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${exoToken.token}`,
            "Content-Type": "application/json",
            "X-ResponseFormat": "json",
          },
          body: JSON.stringify({
            CmdletInput: {
              CmdletName: "Get-HostedOutboundSpamFilterPolicy",
              Parameters: {},
            },
          }),
        });
      },
      io
    );
    if (exoForwardPolicy) {
      io.saveJson("18_exo_outbound_spam_policy.json", exoForwardPolicy);
      // Parse AutoForwardingMode if present in nested structure
      const raw = JSON.stringify(exoForwardPolicy);
      const m = raw.match(/AutoForwardingMode"\s*:\s*"([^"]+)"/i);
      if (m) {
        summary.autoForwardingMode = m[1];
        if (String(m[1]).toLowerCase() === "on" || String(m[1]).toLowerCase() === "automatic") {
          findings.push({
            Severity: "High",
            Area: "MailboxForwarding",
            Detail: `Outbound AutoForwardingMode=${m[1]} — users may auto-forward to external addresses`,
          });
        } else {
          findings.push({
            Severity: "Info",
            Area: "MailboxForwarding",
            Detail: `Outbound AutoForwardingMode=${m[1]}`,
          });
        }
      }
    }
  } else {
    findings.push({
      Severity: "Info",
      Area: "MailboxForwarding",
      Detail:
        "No Exchange Admin token captured — open admin.exchange.microsoft.com during collection, or check Anti-spam outbound AutoForwardingMode + Remote Domains manually",
    });
  }

  // Per-user SMTP forwarding via Graph is not exposed; hunting when EmailEvents exists
  if (schema.canHunt && schema.has("EmailEvents")) {
    // EmailEvents carries EmailSize and AttachmentCount, so outbound flow can be
    // ranked by data volume rather than message count — a hundred one-line
    // replies and a hundred messages carrying attachments are the same number
    // otherwise, and only one of them is an exfiltration shape.
    const fwdHunt = await soft(
      "forwardingHunting",
      () =>
        graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
          Query: `
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Outbound"
| where SenderFromAddress has "@"
| extend DestDomain = tostring(split(RecipientEmailAddress,"@")[1])
| where isnotempty(DestDomain)
| summarize OutboundCount=count(), Senders=dcount(SenderFromAddress), TotalBytes=sum(EmailSize), WithAttachments=countif(AttachmentCount > 0), MaxBytes=max(EmailSize), LastSeen=max(Timestamp) by DestDomain
| sort by TotalBytes desc
| take 60
`.trim(),
        }),
      io
    );
    if (fwdHunt && fwdHunt.results) {
      io.saveCsv(
        "18_Outbound_Email_Domains_30d.csv",
        fwdHunt.results.map((r) => ({
          DestDomain: r.DestDomain,
          OutboundCount: r.OutboundCount,
          Senders: r.Senders,
          WithAttachments: r.WithAttachments,
          TotalBytes: r.TotalBytes,
          TotalMB: Math.round((Number(r.TotalBytes) || 0) / 1048576),
          MaxMB: Math.round((Number(r.MaxBytes) || 0) / 1048576),
          LastSeen: r.LastSeen,
        }))
      );
    }

    // Who is sending to consumer mail, with attachments, ranked by volume.
    const consumerHunt = await soft(
      "consumerOutboundHunting",
      () =>
        graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
          Query: `
let consumer = dynamic(["gmail.com","googlemail.com","yahoo.com","yahoo.fr","hotmail.com","hotmail.fr","outlook.com","outlook.fr","live.com","live.fr","icloud.com","me.com","proton.me","protonmail.com","gmx.com","gmx.fr","orange.fr","free.fr","wanadoo.fr","laposte.net","sfr.fr","aol.com","yandex.ru","mail.ru","qq.com","163.com"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Outbound"
| extend DestDomain = tostring(split(RecipientEmailAddress,"@")[1])
| where DestDomain in~ (consumer)
| summarize Messages=count(), WithAttachments=countif(AttachmentCount > 0), TotalBytes=sum(EmailSize), MaxBytes=max(EmailSize), Domains=make_set(DestDomain, 8), LastSeen=max(Timestamp) by SenderFromAddress
| sort by TotalBytes desc
| take 100
`.trim(),
        }),
      io
    );
    if (consumerHunt && consumerHunt.results) {
      io.saveCsv(
        "18_Consumer_Outbound_BySender_30d.csv",
        consumerHunt.results.map((r) => ({
          Sender: r.SenderFromAddress,
          Messages: r.Messages,
          WithAttachments: r.WithAttachments,
          TotalMB: Math.round((Number(r.TotalBytes) || 0) / 1048576),
          MaxMB: Math.round((Number(r.MaxBytes) || 0) / 1048576),
          Domains: Array.isArray(r.Domains) ? r.Domains.join(" | ") : r.Domains,
          LastSeen: r.LastSeen,
        }))
      );
    }
  } else {
    console.log("  · Skip outbound email domain hunt (EmailEvents unavailable)");
  }

  // Transport-level note file for manual EXO checks
  io.saveCsv("18_Mailbox_Forwarding_Manual_Checks.csv", [
    {
      Check: "Outbound spam policy — Automatic forwarding",
      ExpectedHardened: "Off (block automatic forwarding to external)",
      Portal:
        "security.microsoft.com → Anti-spam → Outbound → Automatic forwarding = Off",
    },
    {
      Check: "Remote domains — AutoForwardEnabled",
      ExpectedHardened: "False for '*' remote domain",
      Portal: "EAC → Mail flow → Remote domains → Default",
    },
    {
      Check: "Per-mailbox ForwardingSmtpAddress / DeliverToMailboxAndForward",
      ExpectedHardened: "None to consumer domains (gmail/outlook/yahoo…)",
      Portal: "EXO: Get-Mailbox -ResultSize Unlimited | ? ForwardingSmtpAddress",
    },
    {
      Check: "Inbox rules RedirectTo / ForwardTo external",
      ExpectedHardened: "Monitor / block via transport rules",
      Portal: "EXO Get-InboxRule or Defender hunting",
    },
  ]);

  summary.m365CollabCollected = true;
}

module.exports = { collectM365CollabAndMail, sharingLabel };
