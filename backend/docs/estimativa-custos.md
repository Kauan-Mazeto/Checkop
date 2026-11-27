# Estimativa de custos do Checkop

Consolidada em 26/11/2026, para o slide "planos operacionais" do TCC (Canva).

## Premissas

- Equipe: 2 devs plenos (1 front, 1 back), R$ 150/h.
- Desenvolvimento: 180 h no total (90 h front + 90 h back), cerca de 4 meses.
- Manutenção: 10 h por mês no início.
- Servidor: Hostinger VPS KVM 8 (8 vCPU, 32 GB RAM, 400 GB NVMe, 32 TB de banda).
  - Contrato de 24 meses: R$ 2.879,76, que dá R$ 119,99 por mês.
  - Renovação: R$ 259,99 por mês.
  - Fonte: site da Hostinger, consultado em 26/11/2026.
- Cotação usada: US$ 1 = R$ 5,80.

## 1. Desenvolvimento (180 h)

| Item | Premissa | Valor |
|---|---|---:|
| Mão de obra | 180 h × R$ 150 | R$ 27.000 |
| Computadores | 2 notebooks de ~R$ 5.000, depreciação dos 4 meses | R$ 1.110 |
| Internet | Fibra, 2 devs × 4 meses | R$ 880 |
| Energia | 90 h × ~90 W × R$ 1,05/kWh × 2 devs | R$ 20 |
| Assinatura de IA para os devs | Claude Pro, 2 × 4 meses | R$ 930 |
| API da Anthropic nos testes | | R$ 100 |
| **Subtotal** | | **≈ R$ 30.040** |

## 2. Operação mensal

| Item | Por mês |
|---|---:|
| Servidor (Hostinger VPS KVM 8) | R$ 119,99 |
| Domínio .com.br (Registro.br, R$ 40 por ano) | R$ 3 |
| Certificado HTTPS (Let's Encrypt) | R$ 0 |
| DeepL API Pro (US$ 5,49 + uso) | R$ 177 |
| API da Anthropic (Opus 5.5) | R$ 406 |
| Manutenção (10 h × R$ 150) | R$ 1.500 |
| **Total** | **≈ R$ 2.206** |

## 3. Custo geral

| | Valor |
|---|---:|
| Desenvolvimento | R$ 30.040 |
| Operação no 1º ano (12 × R$ 2.206) | R$ 26.472 |
| **1º ano** | **≈ R$ 56.510** |
| 2º ano (só operação) | ≈ R$ 26.472 |
| A partir do 3º ano (servidor a R$ 259,99) | ≈ R$ 28.152 por ano |

## Texto para o slide

**Desenvolvimento:** ~R$ 30 mil (180 h).

**Operação:** ~R$ 2,2 mil por mês.

**Total:** ~R$ 56,5 mil no primeiro ano.

Rodapé: "Servidor: Hostinger VPS KVM 8, plano de 24 meses, consultado em 26/11/2026".

Comparação: o mesmo sistema feito sem IA levaria cerca de 1.300 h, ou ~R$ 195 mil só de mão de obra. As 180 h representam cerca de 7 vezes menos esforço.
