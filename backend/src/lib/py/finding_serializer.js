import { getComplianceNotes } from '../../constants/compliance_mapping.js';

// RF-07 / RF-08
export const serializeFinding = (finding, { safeMode }) => {
    const compliance = getComplianceNotes(finding.owaspUrl);

    if (!safeMode) {
        return { ...finding, compliance };
    }

    return {
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        tool: finding.tool,
        affectedUrl: finding.affectedUrl,
        cveId: finding.cveId,
        cvssScore: finding.cvssScore,
        owaspUrl: finding.owaspUrl,
        remediation: finding.remediation,
        createdAt: finding.createdAt,
        compliance,
    };
};

export const serializeFindings = (findings, options) =>
    findings.map((finding) => serializeFinding(finding, options));