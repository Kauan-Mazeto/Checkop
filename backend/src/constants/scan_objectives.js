// Mapeia "o que o usuário quer testar" para a configuração real de cada motor.
// Adicionar um objetivo novo = adicionar uma entrada aqui, nada mais.
export const SCAN_OBJECTIVES = {
    SQL_INJECTION: {
        label: 'Injeção de SQL (SQLi)',
        engines: ['NUCLEI', 'ZAP'],
        nuclei: { tags: ['sqli'] },
        zap: { scannerIds: ['40018', '40019', '40020', '40021', '40022', '40024', '90019'] },
    },
    XSS: {
        label: 'Cross-Site Scripting (XSS)',
        engines: ['NUCLEI', 'ZAP'],
        nuclei: { tags: ['xss'] },
        zap: { scannerIds: ['40012', '40014', '40016', '40017'] },
    },
    CSRF: {
        label: 'Cross-Site Request Forgery (CSRF)',
        engines: ['ZAP'],
        nuclei: null,
        zap: { scannerIds: ['20012'] },
    },
    SSRF: {
        label: 'Server-Side Request Forgery (SSRF)',
        engines: ['NUCLEI', 'ZAP'],
        nuclei: { tags: ['ssrf'] },
        zap: { scannerIds: ['40046', '40047', '40048', '40049'] },
    },
    OPEN_REDIRECT: {
        label: 'Open Redirect',
        engines: ['NUCLEI', 'ZAP'],
        nuclei: { tags: ['redirect'] },
        zap: { scannerIds: ['10044'] },
    },
    KNOWN_CVE: {
        label: 'CVEs conhecidas e má configuração',
        engines: ['NUCLEI'],
        nuclei: { tags: ['cve', 'misconfig', 'exposure', 'default-login'] },
        zap: null,
    },
    SUBDOMAIN_ENUM: {
        label: 'Enumeração de subdomínios',
        engines: ['SUBFINDER'],
        nuclei: null,
        zap: null,
    },
    FULL_SCAN: {
        label: 'Varredura completa (todas as categorias)',
        engines: ['NUCLEI', 'ZAP'],
        // NULL por que rodará todos
        nuclei: { tags: [] },  
        zap: { scannerIds: null }, 
    },
};

export const isValidObjective = (value) => Object.prototype.hasOwnProperty.call(SCAN_OBJECTIVES, value);