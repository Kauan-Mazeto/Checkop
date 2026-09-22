// RF-07 / RF-08
export const serializeFinding = (finding, { safeMode }) => {
    if (!safeMode) {
        return finding;
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
    };
};

export const serializeFindings = (findings, options) =>
    findings.map((finding) => serializeFinding(finding, options));