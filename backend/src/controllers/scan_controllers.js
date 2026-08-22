import prisma from '../lib/prisma.js';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';

const serializeIps = (ips) => ips.join(',');
const deserializeIps = (value) => (value ? value.split(',') : []);

const createScan = async (req, res) => {
  try {
    const { targetUrl } = req.body;

    let detection;
    try {
      detection = await detectEnvironment(targetUrl);
    } catch (err) {
      if (err instanceof ScanValidationError) {
        return res.status(400).json({ error: err.message });
      }
      throw err;
    }

    const { environment, resolvedIps, suspicious } = detection;
    const safeMode = environment === 'PRODUCTION';

    const scan = await prisma.scan.create({
      data: {
        targetUrl,
        environment,
        safeMode,
        resolvedIps: serializeIps(resolvedIps),
        suspiciousEnvironment: suspicious,
        userId: req.userId,
        authorizationConfirmedAt: new Date(),
        authorizationIp: req.ip,
      },
    });

    return res.status(201).json({
      message: 'Varredura registrada com sucesso.',
      scan: {
        id: scan.id,
        targetUrl: scan.targetUrl,
        environment: scan.environment,
        safeMode: scan.safeMode,
        status: scan.status,
        suspiciousEnvironment: scan.suspiciousEnvironment,
        resolvedIps: deserializeIps(scan.resolvedIps),
        createdAt: scan.createdAt,
      },
    });
  } catch (error) {
    console.error('Erro ao criar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao registrar varredura.' });
  }
};

const listScans = async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        targetUrl: true,
        environment: true,
        safeMode: true,
        status: true,
        suspiciousEnvironment: true,
        resolvedIps: true,
        createdAt: true,
        startedAt: true,
        finishedAt: true,
      },
    });

    const serialized = scans.map((scan) => ({
      ...scan,
      resolvedIps: deserializeIps(scan.resolvedIps),
    }));

    return res.status(200).json({ scans: serialized });
  } catch (error) {
    console.error('Erro ao listar varreduras:', error);
    return res.status(500).json({ error: 'Erro interno ao listar varreduras.' });
  }
};

const listSuspiciousScans = async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: {
        userId: req.userId,
        suspiciousEnvironment: true,
      },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        targetUrl: true,
        resolvedIps: true,
        environment: true,
        createdAt: true,
      },
    });

    const serialized = scans.map((scan) => ({
      ...scan,
      resolvedIps: deserializeIps(scan.resolvedIps),
    }));

    return res.status(200).json({ scans: serialized });
  } catch (error) {
    console.error('Erro ao listar varreduras suspeitas:', error);
    return res.status(500).json({ error: 'Erro interno ao listar varreduras suspeitas.' });
  }
};

const getScanById = async (req, res) => {
  try {
    const findings = await prisma.finding.findMany({
      where: { scanId: req.resource.id },
    });

    return res.status(200).json({
      scan: {
        ...req.resource,
        resolvedIps: deserializeIps(req.resource.resolvedIps),
        findings,
      },
    });
  } catch (error) {
    console.error('Erro ao buscar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar varredura.' });
  }
};

export default { createScan, listScans, listSuspiciousScans, getScanById };