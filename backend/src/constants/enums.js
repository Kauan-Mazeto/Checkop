const Role = Object.freeze({
    DEV: 'DEV',
    QA: 'QA',
    PENTESTER: 'PENTESTER',
    STUDENT: 'STUDENT'
  });
  
  const TargetEnvironment = Object.freeze({
    DEVELOPMENT: 'DEVELOPMENT',
    STAGING: 'STAGING',
    PRODUCTION: 'PRODUCTION'
  });
  
  const ScanStatus = Object.freeze({
    PENDING: 'PENDING',
    RUNNING: 'RUNNING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED'
  });
  
  const FindingSeverity = Object.freeze({
    INFO: 'INFO',
    LOW: 'LOW',
    MEDIUM: 'MEDIUM',
    HIGH: 'HIGH',
    CRITICAL: 'CRITICAL'
  });
  
  const FindingStatus = Object.freeze({
    OPEN: 'OPEN',
    FALSE_POSITIVE: 'FALSE_POSITIVE',
    FIXED: 'FIXED',
    IGNORED: 'IGNORED'
  });
  
  const ToolType = Object.freeze({
    OWASP_ZAP: 'OWASP_ZAP',
    NUCLEI: 'NUCLEI'
  });
  
  export {
    Role,
    TargetEnvironment,
    ScanStatus,
    FindingSeverity,
    FindingStatus,
    ToolType
  };