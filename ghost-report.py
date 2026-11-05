#!/usr/bin/env python3
"""
Ghost-Report v1.0.0 - Unified Pentest Report Generator
=======================================================
Ingere JSON output de qualquer ghost-* tool e gera relatorio
HTML profissional com executive summary, findings tecnicos,
CVSS-like scoring, timeline e recomendacoes de remediacao.

Uso:
  python ghost-report.py --input recon.json fuzz.json cloud.json
  python ghost-report.py --input *.json --output relatorio.html
  python ghost-report.py --input resultados/ --title "Pentest ACME Corp"
  python ghost-report.py --input scan.json --format markdown
  python ghost-report.py --demo

Autor: By Gh0st-Bx1 | github.com/Ghost-Bx1
"""

import argparse
import glob
import hashlib
import json
import math
import os
import sys
from datetime import datetime

VERSAO = "2.0.0"


def _build_banner():
    import re as _re
    G = "\033[92m"; Cy = "\033[96m"; D = "\033[2m"; N = "\033[1m"
    W = "\033[97m"; X = "\033[0m"
    IW = 68; eq = "═" * IW; sp = " " * IW
    TL = "╔"; TR = "╗"; BL = "╚"; BR = "╝"; VB = "║"
    hl = "─" * 44; bar = "│"
    vl = lambda s: len(_re.sub(r"\x1b\[[0-9;]*m", "", s))

    def _row(s):
        n = vl(s); p = max(0, IW - n); l = p // 2; r = p - l
        return f"{G}{VB}{X}{' ' * l}{s}{' ' * r}{G}{VB}{X}"

    def _row_l(s):
        n = vl(s); p = max(0, IW - n - 2)
        return f"{G}{VB}{X}  {s}{' ' * p}{G}{VB}{X}"

    ga = [
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠛⠿⠟⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⢀⣠⣤⣶⣶⣶⣶⣶⣶⣤⣀⠢⢝⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡡⢀⣴⡿⢋⡴⢿⣿⣿⣿⣿⣿⣿⣿⢷⣦⡑⠈⡛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⡜⢠⣾⣿⣤⣋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣶⣦⣤⣤⣀⠉⠻⣿⣿⣿⡿⠿⢛⢛⡻⠿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⠿⠟⠟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⢀⣿⣿⣿⡿⠛⠛⠻⣿⣿⣿⡿⠛⠛⢿⣿⣿⣧⠉⠉⣁⣈⣉⣁⢀⣿⣿⢋⠄⣁⣴⣶⣄⠐⢌⢻⣿⣿{X}", ""),
        ("", f"{G}⡏⠀⣴⣦⣄⠢⡙⢿⣿⣿⣿⣿⣿⣿⡇⠀⣼⣿⣿⣿⠅⠀⠀  ⢹⣿⡿⠁⠀⠀⠀⢹⣿⣿⡆⠀⣿⣿⣿⣿⣿⡟⠁⢀⣴⣿⣿⣿⣿⣷⡈⠎⢿⣿{X}", ""),
        ("", f"{G}⡇⠀⣿⣿⣿⣷⣌⠀⠙⢿⣿⣿⣿⣿⠀⢀⣿⣿⣿⣿⠀⠀⠀  ⠀⠈⣿⡇⠀⠀⠀⠀⠈⢿⣿⡇⠁⢻⣿⣿⣿⡿⠁⢠⣾⣿⣿⣿⡿⢿⣿⣷⠀⠘⣿{X}", ""),
        ("", f"{G}⣇⠀⢿⣿⣿⡟⣿⣷⣄⠀⠙⢿⣿⡇⠀⣸⣿⣿⡿⣿⡀⠀⠀⠀  ⢸⣿⣧⠀⠀⠀⠀⣸⡈⣿⣷⠀⡈⣿⣿⡿⠁⢀⣾⣿⣿⢩⣿⠁⣾⣿⣿⡆⠀⢿{X}", ""),
        ("", f"{G}⣿⡀⠘⣿⣿⣿⡘⣿⣿⣷⣌⠂⠉⠁⢠⣿⣿⡟⣰⢿⣷⣤⣤⣴⣿⣿⣿⣷⣄⣠⣴⣿⣧⠸⣿⣧⡐⠢⠉⠁⢀⣾⣿⣿⡇⣼⣿⢸⣿⣿⣿⣇⠀⢸{X}", ""),
        ("", f"{G}⣿⣷⡀⠸⣿⣿⣧⠸⣿⣿⣿⣿⣶⣶⣿⣿⠏⡰⢃⣾⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣏⠳⣘⣿⣿⣷⣶⣾⣿⣿⣿⣿⢠⣿⣿⣿⣿⣿⣿⣿⠀⢸{X}", ""),
        ("", f"{G}⣿⣿⡇⠀⣿⣿⣿⡄⡿⢿⣿⣿⣿⣿⣿⣷⣾⣷⣿⣿⣿⣿⣿⣿⣧⣀⣠⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠋⢉⠉⡉⠛⠿⣿⠀⢸{X}", ""),
        ("", f"{G}⣿⣿⡇⢀⣿⣿⣿⣧⢸⡘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⢠⣾⣿⡄⠈⠀⠀⠀⠀ ⣾{X}", ""),
        ("", f"{G}⣿⡟⠀⣸⣿⣿⣿⣿⣜⡇⢿⣧⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡉⠻⠇⠀⠰⠀⠀ ⣀⣾{X}", ""),
        ("", f"{G}⣿⠃⢠⣿⣿⠿⠿⠿⢿⣿⠸⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢣⢸⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⢰⠜⠋⠀⢀⡄⢰⣤⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠃⢻⣿⣿{X}", ""),
        ("", f"{G}⣿⣆⠠⠀⡀⠀⠁⣿⣿⠟⠀⣽⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⣿⣿⣿⣿⣿⢃⣿⣿⣿⡟⣸⣿⣿⣿⣿⡿⠋⢠⢃⣾⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣷⣶⠆⡄⠈⢉⣠⣴⣾⣿⢿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢋⣴⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⠇⠛⢏⠉⠉⠁⠤⢊⣥⣾⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⢄⠀⢾⣿⣿⣿⣿⡇⢸⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣶⣬⣭⣶⣾⣿⣿⠏⣼⣿⣿⣿⡇⣸⣿⣿⣿⠀⣰⣿⡁⢠⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣤⣀⡀⠀⠀⠉⠉⠁⢸⣿⣿⣿⢸⣿⣿⣿⣿⡹⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣿⣿⣿⣿⠇⣿⣿⣿⣿⡀⠹⢿⡇⠀⢿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠛⠀⣼⣿⣿⣿⢸⣿⣿⢻⣿⣷⣌⠻⣿⣿⣿⣿⠟⣡⣾⣿⡟⣼⣿⣿⠀⣿⣿⣿⣿⣿⣶⣤⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⠈⠀⣴⣾⣿⣿⣿⡇⢸⣿⣿⣇⢻⣿⣿⣷⣦⣭⣭⣴⣾⣿⣿⣿⢡⣿⣿⣿⠀⣿⣿⣿⣿⣿⠿⠟⠃⡀⢸⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⡐⠠⢈⡉⠛⠛⠿⡇⢸⣿⣿⣿⡜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⣿⣿⣿⠀⣁⣤⡄⠀⣀⣒⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⡌⠀⣦⠀⣼⣿⣿⣿⣇⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣿⣿⣿⣿⣄⡈⠛⠃⠐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⢁⣤⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⡟⢸⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠠⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⢼⠿⠿⣿⣿⣿⣿⠟⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠈⣙⠛⠛⣛⣛⠛⠀⠻⢿⣿⣿⣿⣿⣿⣿⡃⢠⣤⠀⠀⣀⣉⣁⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣤⡀⢀⠈⢿⣿⣿⣿⣿⣷⣄⠁⠀⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠁⠈⣿⣿⣿⣿⣿⣿⡆⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠠⢠⣿⣿⣿⣿⣿⠟⢀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡗⠀⢸⣿⣿⣿⡿⢁⡄⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠰⠘⣿⣿⣿⠁⠎⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡑⠈⠻⠇⠈⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
    ]

    info = [
        f"{G}{N}GHOST-REPORT{X}",
        f"{Cy}v{VERSAO}  {D}Unified Pentest Report Generator{X}",
        f"{D}{hl}{X}",
        f"{W}By Gh0st-Bx1  {D}{bar}  github.com/Ghost-Bx1{X}",
        f"{D}{hl}{X}",
        f"{D}--input <json...>  --output relatorio.html{X}",
        f"{D}HTML report com executive summary + CVSS scoring{X}",
    ]

    out = [f"{G}{TL}{eq}{TR}{X}", f"{G}{VB}{sp}{VB}{X}"]
    for left, center, right in ga:
        combined = left + center + right
        out.append(_row(combined))
    out.append(f"{G}{VB}{sp}{VB}{X}")
    for i in info:
        out.append(_row_l(i))
    out += [f"{G}{VB}{sp}{VB}{X}", f"{G}{BL}{eq}{BR}{X}"]
    return "\n".join(out)


BANNER = _build_banner()

C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m",
    "B": "\033[94m", "M": "\033[95m", "C": "\033[96m",
    "W": "\033[97m", "X": "\033[0m",  "N": "\033[1m", "D": "\033[2m",
}


# ─── Ingestao de dados ────────────────────────────────────────────────────────

def load_inputs(paths: list) -> list:
    """Carrega arquivos JSON ou pastas. Retorna lista de dicts."""
    results = []
    expanded = []
    for p in paths:
        if os.path.isdir(p):
            expanded.extend(glob.glob(os.path.join(p, "*.json")))
        elif "*" in p or "?" in p:
            expanded.extend(glob.glob(p))
        else:
            expanded.append(p)
    for path in expanded:
        if not os.path.exists(path):
            print(f"  {C['Y']}[AVISO]{C['X']} Arquivo nao encontrado: {path}")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            data["_source_file"] = os.path.basename(path)
            results.append(data)
            print(f"  {C['G']}[OK]{C['X']} Carregado: {path}")
        except Exception as e:
            print(f"  {C['R']}[ERRO]{C['X']} {path}: {e}")
    return results


# ─── Normalizacao de findings ─────────────────────────────────────────────────

SEVERITY_MAP = {
    "critical": 4, "critico": 4, "crit": 4,
    "high": 3, "alto": 3,
    "medium": 2, "med": 2, "medio": 2,
    "low": 1, "baixo": 1,
    "info": 0, "informational": 0,
}

REMEDIATION = {
    "s3": "Configurar bucket policy para negar acesso publico. Habilitar S3 Block Public Access.",
    "blob": "Definir container access level como Private. Usar SAS tokens com TTL curto.",
    "gcs": "Configurar IAM para negar allUsers e allAuthenticatedUsers.",
    "imds": "Habilitar IMDSv2 obrigatorio (hop limit=1). Bloquear acesso ao 169.254.169.254 de containers.",
    "iac": "Remover arquivos de estado/configuracao do webroot. Usar .gitignore para segredos.",
    "sqli": "Usar prepared statements / parameterized queries. Nunca concatenar input diretamente.",
    "xss": "Sanitizar output com htmlspecialchars. Implementar CSP header.",
    "ssrf": "Validar e restringir URLs permitidas. Bloquear acesso a metadata endpoints internos.",
    "lfi": "Usar whitelist de paths permitidos. Desabilitar allow_url_include no PHP.",
    "cors": "Definir Access-Control-Allow-Origin com lista de origens permitidas. Nunca usar wildcard com credenciais.",
    "open_redirect": "Validar que redirect URL pertence ao dominio proprio.",
    "waf": "WAF detectado - pode requerer evasion para testes adicionais.",
    "ssl": "Atualizar configuracao TLS. Desabilitar SSLv3/TLS1.0/1.1. Usar cipher suites fortes.",
    "default": "Revisar e corrigir a configuracao identificada seguindo as melhores praticas de seguranca.",
    "broken_auth": "Implementar MFA. Usar tokens JWT com expiracao curta. Proteger endpoints de autenticacao com rate limiting.",
    "injection": "Usar prepared statements. Nunca interpolar input do usuario em comandos. Validar e sanitizar entradas.",
    "rce": "Nunca executar comandos construidos a partir de input externo. Usar APIs nativas no lugar de shell_exec/system.",
    "xxe": "Desabilitar processamento de entidades externas no parser XML. Usar JSON onde possivel.",
    "deserialization": "Validar e assinar objetos serializados. Usar allowlist de classes. Nunca desserializar dados externos sem validacao.",
    "idor": "Implementar autorizacao baseada em objetos (RBAC/ABAC). Verificar ownership em cada request.",
    "path_traversal": "Usar basename() para extrair nomes de arquivo. Nunca concatenar input em paths de filesystem.",
    "csrf": "Implementar CSRF tokens validos por sessao. Usar SameSite=Strict em cookies de sessao.",
    "misconfig": "Seguir CIS Benchmarks para o componente afetado. Remover servicos, usuarios e configuracoes desnecessarias.",
    "secrets": "Rotacionar credenciais expostas imediatamente. Usar secrets manager (Vault, AWS SSM, Azure Key Vault).",
    "ad_cs": "Desabilitar CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT em templates. Remover permissoes de enrollment de grupos nao-privilegiados.",
    "kerberoast": "Usar senhas longas (>25 chars) em contas de servico. Migrar para gMSA. Habilitar AES-256.",
    "dcsync": "Remover DS-Replication-Get-Changes-All de contas nao-DCs. Auditar via BloodHound regularmente.",
    "laps": "Implantar LAPS (Microsoft LAPS ou Windows LAPS) em todos os workstations e servidores membros.",
    "privilege_escalation": "Seguir principio do minimo privilegio. Auditar grupos privilegiados. Revisar sudoers/token privileges.",
    "cloud_iam": "Aplicar principio do minimo privilegio. Remover wildcards de policies IAM. Revisar roles assumiveis.",
    "exposed_service": "Restringir acesso por Security Group / firewall. Habilitar autenticacao. Monitorar com CloudWatch/SIEM.",
}


# ─── CVSS v3.1 Calculator ─────────────────────────────────────────────────────

def cvss_score(vector: str) -> float:
    """Calcula CVSS v3.1 a partir de vector string (CVSS:3.1/AV:N/AC:L/...)."""
    _AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    _AC  = {"L": 0.77, "H": 0.44}
    _PRU = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PRC = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI  = {"N": 0.85, "R": 0.62}
    _CIA = {"N": 0.0,  "L": 0.22, "H": 0.56}
    try:
        parts = {}
        for seg in vector.split("/"):
            if ":" in seg:
                k, v = seg.split(":", 1)
                parts[k] = v
        scope = parts.get("S", "U")
        av  = _AV.get(parts.get("AV", "N"), 0.85)
        ac  = _AC.get(parts.get("AC", "L"), 0.77)
        pr  = (_PRC if scope == "C" else _PRU).get(parts.get("PR", "N"), 0.85)
        ui  = _UI.get(parts.get("UI", "N"), 0.85)
        c   = _CIA.get(parts.get("C", "N"), 0.0)
        i   = _CIA.get(parts.get("I", "N"), 0.0)
        a   = _CIA.get(parts.get("A", "N"), 0.0)
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = (7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
                  if scope == "C" else 6.42 * iss)
        exploit = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = (min(1.08 * (impact + exploit), 10.0)
               if scope == "C" else min(impact + exploit, 10.0))
        return math.ceil(raw * 10) / 10
    except Exception:
        return 0.0


def normalize_findings(datasets: list) -> list:
    """Normaliza findings de diferentes ghost-* tools para formato unificado."""
    normalized = []
    for ds in datasets:
        source = ds.get("_source_file", "unknown")
        target = ds.get("target", ds.get("domain", ds.get("host", "N/A")))
        findings = ds.get("findings", ds.get("results", ds.get("vulnerabilities", {})))

        if isinstance(findings, dict):
            items = []
            for cat, vals in findings.items():
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, dict):
                            items.append((cat, v))
                elif isinstance(vals, dict):
                    items.append((cat, vals))
        elif isinstance(findings, list):
            items = [("finding", f) for f in findings if isinstance(f, dict)]
        else:
            items = []

        for cat, item in items:
            sev_raw = item.get("severity", item.get("risk", item.get("level", "info"))).lower()
            severity = SEVERITY_MAP.get(sev_raw, 0)

            url = item.get("url", item.get("endpoint", item.get("bucket", "")))
            title = item.get("title", item.get("type", item.get("check", cat)))
            desc = item.get("description", item.get("details", item.get("note",
                   item.get("body", str(item)[:200]))))
            cvss = item.get("cvss", item.get("score", None))

            if cvss is None:
                cvss_vec = item.get("cvss_vector", item.get("vector", ""))
                if cvss_vec and ("AV:" in cvss_vec or "CVSS:" in cvss_vec):
                    cvss = cvss_score(cvss_vec)
                if not cvss:
                    cvss = [0, 3.9, 5.9, 7.9, 9.9][min(severity, 4)]

            remediation = item.get("remediation", REMEDIATION.get(cat.lower(),
                          REMEDIATION["default"]))

            normalized.append({
                "source": source,
                "target": target,
                "category": cat,
                "title": str(title),
                "description": str(desc)[:500],
                "severity": severity,
                "severity_label": ["Info", "Low", "Medium", "High", "Critical"][min(severity, 4)],
                "cvss": round(float(cvss), 1),
                "url": str(url),
                "remediation": remediation,
                "raw": item,
            })

    normalized.sort(key=lambda x: x["severity"], reverse=True)
    return normalized


# ─── Deduplicacao e Diff ──────────────────────────────────────────────────────

def dedup_findings(findings: list) -> list:
    """Remove findings duplicados por hash de titulo+categoria."""
    seen = set()
    result = []
    for f in findings:
        key = f"{f['title'].strip().lower()}::{f['category'].strip().lower()}"
        h = hashlib.md5(key.encode()).hexdigest()[:12]
        if h not in seen:
            seen.add(h)
            result.append(f)
    return result


def _finding_hash(f: dict) -> str:
    key = f"{f['title'].strip().lower()}::{f['category'].strip().lower()}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def apply_diff(findings: list, prev_path: str) -> list:
    """Marca findings como NEW ou RECURRING comparando com relatorio anterior."""
    prev_hashes = set()
    try:
        with open(prev_path, encoding="utf-8") as fh:
            prev = json.load(fh)
        for pf in prev.get("findings", []):
            if isinstance(pf, dict):
                key = f"{str(pf.get('title','')).strip().lower()}::{str(pf.get('category','')).strip().lower()}"
                prev_hashes.add(hashlib.md5(key.encode()).hexdigest()[:12])
    except Exception as e:
        print(f"  {C['Y']}[AVISO]{C['X']} diff nao carregado: {e}")
    for f in findings:
        f["diff_status"] = "recurring" if _finding_hash(f) in prev_hashes else "new"
    return findings


def auto_executive_summary(findings: list, target: str, risk_score: float,
                            risk_label: str) -> str:
    """Gera paragrafo de executive summary automaticamente."""
    counts = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    categories: dict = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        categories[f["category"]] = categories.get(f["category"], 0) + 1
    total = len(findings)
    if total == 0:
        return "Nenhum finding identificado nesta avaliacao."
    parts = []
    if counts[4]: parts.append(f"{counts[4]} critico(s)")
    if counts[3]: parts.append(f"{counts[3]} alto(s)")
    if counts[2]: parts.append(f"{counts[2]} medio(s)")
    if counts[1]: parts.append(f"{counts[1]} baixo(s)")
    if counts[0]: parts.append(f"{counts[0]} informativo(s)")
    sev_str = ", ".join(parts)
    top_cats = [c for c, _ in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]]
    t = target or "o alvo avaliado"
    summary = (f"Esta avaliacao de seguranca em {t} identificou {total} finding(s): "
               f"{sev_str}. O risco global e classificado como {risk_label} "
               f"(CVSS medio: {risk_score:.1f}). ")
    if top_cats:
        summary += f"As categorias de maior incidencia foram: {', '.join(top_cats)}. "
    if counts[4] > 0:
        summary += ("Vulnerabilidades criticas requerem atencao imediata e "
                    "remediacoes prioritarias antes de qualquer nova exposicao. ")
    elif counts[3] > 0:
        summary += "Vulnerabilidades de alto risco devem ser remediadas em curto prazo. "
    return summary


def make_demo_data() -> list:
    """Gera dados de demo para testar o relatorio."""
    return [
        {
            "_source_file": "ghost-recon-demo.json",
            "target": "demo.example.com",
            "findings": {
                "waf": [{"title": "Sem WAF detectado", "severity": "medium",
                          "url": "https://demo.example.com", "description": "Nenhum WAF identificado"}],
                "ssl": [{"title": "TLS 1.0 habilitado", "severity": "high",
                          "url": "https://demo.example.com:443",
                          "description": "Servidor aceita TLS 1.0 (deprecated)"}],
                "headers": [{"title": "HSTS ausente", "severity": "medium",
                              "url": "https://demo.example.com",
                              "description": "Strict-Transport-Security header nao presente"}],
            }
        },
        {
            "_source_file": "ghost-fuzz-demo.json",
            "target": "demo.example.com",
            "findings": {
                "sqli": [{"title": "SQL Injection - parametro id", "severity": "critical",
                           "url": "https://demo.example.com/user?id=1",
                           "description": "Error-based SQLi detectado. MySQL 5.7"}],
                "xss": [{"title": "XSS Refletido - parametro q", "severity": "high",
                          "url": "https://demo.example.com/search?q=<script>",
                          "description": "Input refletido sem sanitizacao"}],
                "cors": [{"title": "CORS wildcard", "severity": "medium",
                           "url": "https://demo.example.com/api/",
                           "description": "Access-Control-Allow-Origin: *"}],
            }
        },
        {
            "_source_file": "ghost-cloud-demo.json",
            "target": "demo.example.com",
            "findings": {
                "s3": [{"title": "S3 bucket publico", "severity": "critical",
                         "url": "https://demo-example-com.s3.amazonaws.com/",
                         "description": "Bucket listavel publicamente com 47 arquivos"}],
                "iac": [{"title": ".env exposto", "severity": "high",
                          "url": "https://demo.example.com/.env",
                          "description": "DB_PASSWORD e API_KEY expostos"}],
            }
        },
    ]


# ─── Geracao HTML ─────────────────────────────────────────────────────────────

SEV_COLOR = {
    4: "#ff3d3d",
    3: "#ffb300",
    2: "#00bcd4",
    1: "#69f0ae",
    0: "#607d8b",
}

SEV_BG = {
    4: "rgba(255,61,61,.12)",
    3: "rgba(255,179,0,.1)",
    2: "rgba(0,188,212,.1)",
    1: "rgba(105,240,174,.1)",
    0: "rgba(96,125,139,.1)",
}


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# Risk level colors: Extreme, High, Medium, Low
_RM_COLORS = {
    "E": "#ff3d3d", "H": "#ffb300", "M": "#00bcd4", "L": "#2e7d32",
}
_RM_GRID = [
    # col: Insignif  Minor    Moderate  Major     Catastrophic
    ["M",  "M",      "H",     "H",      "E"],   # row: Almost Certain
    ["L",  "M",      "H",     "H",      "E"],   # Likely
    ["L",  "L",      "M",     "H",      "H"],   # Possible
    ["L",  "L",      "L",     "M",      "H"],   # Unlikely
    ["L",  "L",      "L",     "L",      "M"],   # Rare
]
_RM_ROWS = ["Almost Certain", "Likely", "Possible", "Unlikely", "Rare"]
_RM_COLS = ["Insignificant", "Minor", "Moderate", "Major", "Catastrophic"]
_SEV_TO_CELL = {4: (0, 4), 3: (1, 3), 2: (2, 2), 1: (3, 1), 0: (4, 0)}


def _risk_matrix_html(findings: list) -> str:
    """Gera tabela HTML 5x5 risk matrix com counts por severidade."""
    cell_counts: dict = {}
    for f in findings:
        rc = _SEV_TO_CELL.get(f["severity"], (4, 0))
        cell_counts[rc] = cell_counts.get(rc, 0) + 1

    rows_html = ""
    for ri, row_label in enumerate(_RM_ROWS):
        cells = ""
        for ci, col_label in enumerate(_RM_COLS):
            lvl = _RM_GRID[ri][ci]
            bg = _RM_COLORS[lvl]
            cnt = cell_counts.get((ri, ci), 0)
            cnt_html = (f'<span style="font-size:18px;font-weight:700;color:#fff">{cnt}</span>'
                        if cnt else "")
            cells += (f'<td style="background:{bg}22;border:1px solid {bg}44;'
                      f'color:{bg};text-align:center;padding:10px 6px;min-width:80px">'
                      f'{cnt_html}</td>')
        rows_html += f'<tr><td style="padding:6px 10px;color:var(--fg-dim);font-size:11px;white-space:nowrap">{row_label}</td>{cells}</tr>'

    header_cells = "".join(
        f'<th style="padding:6px 8px;font-size:10px;color:var(--fg-dim);font-weight:600;text-transform:uppercase;letter-spacing:.05em">{c}</th>'
        for c in _RM_COLS)
    legend = " ".join(
        f'<span style="display:inline-flex;align-items:center;gap:4px;font-size:11px">'
        f'<span style="width:10px;height:10px;border-radius:2px;background:{_RM_COLORS[k]};display:inline-block"></span>'
        f'<span style="color:var(--fg-dim)">{v}</span></span>'
        for k, v in [("E", "Extreme"), ("H", "High"), ("M", "Medium"), ("L", "Low")])
    return (f'<div style="overflow-x:auto;margin-top:8px">'
            f'<div style="font-size:10px;color:var(--fg-dim);margin-bottom:6px;letter-spacing:.05em">LIKELIHOOD / IMPACT</div>'
            f'<table style="border-collapse:collapse;width:100%">'
            f'<tr><th></th>{header_cells}</tr>{rows_html}</table>'
            f'<div style="margin-top:8px;display:flex;gap:12px;flex-wrap:wrap">{legend}</div>'
            f'</div>')


def generate_html(findings: list, title: str, author: str, target: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    total = len(findings)
    risk_score = sum(f["cvss"] for f in findings) / max(total, 1)
    risk_label = "CRITICO" if risk_score >= 7 else "ALTO" if risk_score >= 4 else "MEDIO" if risk_score >= 2 else "BAIXO"
    risk_color = "#ff3d3d" if risk_score >= 7 else "#ffb300" if risk_score >= 4 else "#00bcd4" if risk_score >= 2 else "#69f0ae"

    exec_summary = auto_executive_summary(findings, target, risk_score, risk_label)
    risk_matrix = _risk_matrix_html(findings)

    findings_html = ""
    for i, f in enumerate(findings, 1):
        sc = SEV_COLOR.get(f["severity"], "#607d8b")
        sb = SEV_BG.get(f["severity"], "rgba(96,125,139,.1)")
        url_html = (f'<a href="{_html_escape(f["url"])}" style="color:#00bcd4;word-break:break-all">'
                    f'{_html_escape(f["url"])}</a>') if f["url"] else "-"
        diff_badge = ""
        if f.get("diff_status") == "new":
            diff_badge = '<span style="background:#00e67622;color:#00e676;border:1px solid #00e67644;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-left:6px">NEW</span>'
        elif f.get("diff_status") == "recurring":
            diff_badge = '<span style="background:#ffb30022;color:#ffb300;border:1px solid #ffb30044;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-left:6px">RECORRENTE</span>'
        findings_html += f"""
        <div class="finding" style="border-left:3px solid {sc};background:{sb}">
          <div class="finding-header">
            <span class="finding-num">#{i:03d}</span>
            <span class="finding-title">{_html_escape(f['title'])}</span>
            <span class="badge" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{f['severity_label']}</span>
            <span class="cvss">CVSS {f['cvss']}</span>{diff_badge}
          </div>
          <div class="finding-body">
            <div class="finding-meta">
              <span class="meta-item"><b>Categoria:</b> {_html_escape(f['category'])}</span>
              <span class="meta-item"><b>Alvo:</b> {_html_escape(f['target'])}</span>
              <span class="meta-item"><b>Fonte:</b> {_html_escape(f['source'])}</span>
            </div>
            <div class="meta-item"><b>URL:</b> {url_html}</div>
            <div class="desc-block"><b>Descricao:</b><br>{_html_escape(f['description'])}</div>
            <div class="remediation-block"><b>Remediacao:</b><br>{_html_escape(f['remediation'])}</div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_html_escape(title)}</title>
<style>
:root {{
  --bg: #0a0c10; --bg2: #0e1117; --bg3: #141920; --border: #1e2d1e;
  --green: #00e676; --cyan: #00bcd4; --amber: #ffb300; --red: #ff3d3d;
  --fg: #c8d6c8; --fg-dim: #5a7a5a; --mono: 'Share Tech Mono', monospace;
  color-scheme: dark;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--fg); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; padding: 0 0 60px; }}
a {{ color: var(--cyan); }}
.header {{ background: var(--bg3); border-bottom: 1px solid var(--border); padding: 40px max(16px, 3vw) 32px; }}
.header h1 {{ font-size: clamp(24px,4vw,40px); font-weight: 700; color: var(--fg); margin-bottom: 6px; }}
.header h1 span {{ color: var(--green); }}
.header-meta {{ color: var(--fg-dim); font-size: 12px; font-family: var(--mono); margin-top: 10px; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 0 max(16px,3vw); }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 12px; margin: 32px 0; }}
.stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 16px 20px; }}
.stat-num {{ font-size: 28px; font-weight: 700; }}
.stat-label {{ font-size: 11px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: .1em; margin-top: 4px; }}
.risk-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 20px; margin-bottom: 28px; display: flex; align-items: center; gap: 20px; }}
.risk-score {{ font-size: 48px; font-weight: 700; }}
.risk-label {{ font-size: 20px; font-weight: 600; }}
.risk-sub {{ font-size: 12px; color: var(--fg-dim); }}
.section-title {{ font-size: 11px; font-weight: 700; letter-spacing: .18em; text-transform: uppercase; color: var(--fg-dim); margin: 28px 0 16px; display: flex; align-items: center; gap: 10px; }}
.section-title::after {{ content: ''; flex: 1; height: 1px; background: var(--border); }}
.finding {{ border-radius: 6px; margin-bottom: 12px; overflow: hidden; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; padding: 12px 16px; flex-wrap: wrap; }}
.finding-num {{ font-family: var(--mono); font-size: 11px; color: var(--fg-dim); }}
.finding-title {{ flex: 1; font-weight: 600; font-size: 14px; }}
.badge {{ padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; font-family: var(--mono); }}
.cvss {{ font-family: var(--mono); font-size: 12px; color: var(--fg-dim); }}
.finding-body {{ padding: 0 16px 14px; }}
.finding-meta {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; font-size: 12px; color: var(--fg-dim); }}
.meta-item {{ font-size: 12px; color: var(--fg-dim); margin-bottom: 4px; }}
.desc-block, .remediation-block {{ font-size: 13px; margin-top: 8px; padding: 8px 12px; background: rgba(0,0,0,.3); border-radius: 4px; }}
.remediation-block {{ border-left: 2px solid var(--green); }}
.footer {{ text-align: center; padding: 40px 16px 0; color: var(--fg-dim); font-size: 12px; font-family: var(--mono); }}
</style>
</head>
<body>
<div class="header">
  <div style="max-width:1100px;margin:0 auto;padding:0 max(16px,3vw)">
    <p style="font-size:11px;color:var(--green);letter-spacing:.15em;text-transform:uppercase;margin-bottom:8px">&gt; Ghost-Report v{VERSAO} - Pentest Report</p>
    <h1>{_html_escape(title)} <span>//</span></h1>
    <div class="header-meta">
      <span>Alvo: {_html_escape(target or 'Multiple')}</span> &nbsp;|&nbsp;
      <span>Autor: {_html_escape(author)}</span> &nbsp;|&nbsp;
      <span>Data: {ts}</span> &nbsp;|&nbsp;
      <span>Total findings: {total}</span>
    </div>
  </div>
</div>

<div class="container">

  <div class="section-title">Executive Summary</div>

  <div class="risk-card">
    <div>
      <div class="risk-score" style="color:{risk_color}">{risk_score:.1f}</div>
      <div class="risk-label" style="color:{risk_color}">{risk_label}</div>
      <div class="risk-sub">Risco medio ponderado CVSS</div>
    </div>
    <div style="flex:1">
      <div style="font-size:13px;color:var(--fg-dim);line-height:1.8">
        {'<br>'.join([
            f'<b style="color:{SEV_COLOR[4]}">{counts[4]} Critico(s)</b>',
            f'<b style="color:{SEV_COLOR[3]}">{counts[3]} Alto(s)</b>',
            f'<b style="color:{SEV_COLOR[2]}">{counts[2]} Medio(s)</b>',
            f'<b style="color:{SEV_COLOR[1]}">{counts[1]} Baixo(s)</b>',
            f'<span>{counts[0]} Info</span>',
        ])}
      </div>
    </div>
  </div>

  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px 20px;margin-bottom:20px;font-size:13px;line-height:1.7;color:var(--fg-dim)">
    {_html_escape(exec_summary)}
  </div>

  <div class="summary">
    <div class="stat-card"><div class="stat-num" style="color:{SEV_COLOR[4]}">{counts[4]}</div><div class="stat-label">Critico</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{SEV_COLOR[3]}">{counts[3]}</div><div class="stat-label">Alto</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{SEV_COLOR[2]}">{counts[2]}</div><div class="stat-label">Medio</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{SEV_COLOR[1]}">{counts[1]}</div><div class="stat-label">Baixo</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--fg-dim)">{total}</div><div class="stat-label">Total</div></div>
  </div>

  <div class="section-title">Risk Matrix</div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px 20px;margin-bottom:28px">
    {risk_matrix}
  </div>

  <div class="section-title">Findings Tecnicos ({total})</div>
  {findings_html if findings_html else '<p style="color:var(--fg-dim);padding:20px 0">Nenhum finding encontrado.</p>'}

  <div class="footer">
    Ghost-Report v{VERSAO} | By Gh0st-Bx1 | github.com/Ghost-Bx1<br>
    Gerado em {ts}
  </div>

</div>
</body>
</html>"""


def generate_markdown(findings: list, title: str, author: str, target: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# {title}", f"**Autor:** {author} | **Alvo:** {target or 'Multiple'} | **Data:** {ts}", ""]
    counts = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines += [
        "## Executive Summary",
        f"| Severidade | Quantidade |",
        f"|---|---|",
        f"| Critico | {counts[4]} |",
        f"| Alto | {counts[3]} |",
        f"| Medio | {counts[2]} |",
        f"| Baixo | {counts[1]} |",
        f"| Info | {counts[0]} |",
        f"| **Total** | **{len(findings)}** |",
        "",
        "## Findings",
        "",
    ]
    for i, f in enumerate(findings, 1):
        lines += [
            f"### #{i:03d} - {f['title']}",
            f"**Severidade:** {f['severity_label']} | **CVSS:** {f['cvss']} | **Categoria:** {f['category']}",
            f"**URL:** {f['url'] or 'N/A'}",
            f"**Descricao:** {f['description']}",
            f"**Remediacao:** {f['remediation']}",
            "",
        ]
    return "\n".join(lines)


# ─── SARIF Export ─────────────────────────────────────────────────────────────

def export_sarif(findings: list, output_path: str):
    """Exporta findings no formato SARIF 2.1.0 para integracao CI/CD."""
    sev_map = {4: "error", 3: "error", 2: "warning", 1: "note", 0: "none"}
    rules = {}
    results = []

    for f in findings:
        rule_id = f.get("category", "unknown").replace(" ", "_").lower()
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("category", "Unknown"),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": f.get("description", "")},
                "help": {"text": f.get("remediation", REMEDIATION.get("default", ""))},
                "properties": {"tags": ["security"], "precision": "medium",
                               "problem.severity": sev_map.get(f.get("severity", 0), "warning")},
            }
        results.append({
            "ruleId": rule_id,
            "level": sev_map.get(f.get("severity", 0), "warning"),
            "message": {"text": f.get("description", f.get("title", ""))},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("url") or f.get("target", "unknown")},
            }}],
            "properties": {
                "cvss": f.get("cvss", 0),
                "severity_label": f.get("severity_label", ""),
                "url": f.get("url", ""),
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Ghost-Report",
                    "version": VERSAO,
                    "informationUri": "https://github.com/Ghost-Bx1",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)
    print(f"  {C['G']}[SARIF]{C['X']} Exportado: {output_path} ({len(results)} results)")


# ─── JSON Findings Export ──────────────────────────────────────────────────────

def export_json_findings(findings: list, output_path: str):
    """Exporta findings normalizados em JSON limpo para integracao."""
    out = []
    for f in findings:
        out.append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "category": f.get("category", ""),
            "severity": f.get("severity", 0),
            "severity_label": f.get("severity_label", ""),
            "cvss": f.get("cvss", 0),
            "url": f.get("url", ""),
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
            "diff_status": f.get("diff_status", ""),
        })
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump({"generated_by": "ghost-report", "version": VERSAO,
                   "count": len(out), "findings": out},
                  fh, indent=2, ensure_ascii=False)
    print(f"  {C['G']}[JSON]{C['X']}  Exportado: {output_path} ({len(out)} findings)")


# ─── Issue Template Generator ─────────────────────────────────────────────────

def generate_issue_template(finding: dict, fmt: str = "jira") -> str:
    """Gera template de issue JIRA ou GitLab Markdown para um finding."""
    sev = finding.get("severity_label", "Unknown")
    title = finding.get("title", "Finding")
    desc = finding.get("description", "")
    url = finding.get("url", "N/A")
    cvss = finding.get("cvss", "N/A")
    rem = finding.get("remediation", REMEDIATION.get("default", ""))
    cat = finding.get("category", "")

    if fmt == "jira":
        return (
            f"h2. {title}\n\n"
            f"*Severidade:* {sev}\n"
            f"*CVSS Score:* {cvss}\n"
            f"*Categoria:* {cat}\n"
            f"*URL/Alvo:* {url}\n\n"
            f"h3. Descricao\n{desc}\n\n"
            f"h3. Remediacao\n{rem}\n\n"
            f"----\n_Gerado por Ghost-Report v{VERSAO} | By Gh0st-Bx1_\n"
        )
    else:  # gitlab
        return (
            f"## {title}\n\n"
            f"| Campo | Valor |\n"
            f"|---|---|\n"
            f"| Severidade | **{sev}** |\n"
            f"| CVSS Score | {cvss} |\n"
            f"| Categoria | {cat} |\n"
            f"| URL/Alvo | `{url}` |\n\n"
            f"### Descricao\n{desc}\n\n"
            f"### Remediacao\n{rem}\n\n"
            f"---\n*Gerado por Ghost-Report v{VERSAO} | By Gh0st-Bx1*\n"
        )


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="Ghost-Report - Unified Pentest Report Generator")
    ap.add_argument("--input", "-i", nargs="+", metavar="FILE",
                    help="Arquivos JSON ou pasta de entrada")
    ap.add_argument("--output", "-o", metavar="FILE", default="ghost-report.html",
                    help="Arquivo de saida (padrao: ghost-report.html)")
    ap.add_argument("--format", choices=["html", "markdown"], default="html",
                    help="Formato de saida (padrao: html)")
    ap.add_argument("--title", default="Pentest Report",
                    help="Titulo do relatorio")
    ap.add_argument("--author", default="Gh0st-Bx1",
                    help="Autor do relatorio")
    ap.add_argument("--target", default="",
                    help="Alvo principal (para cabecalho)")
    ap.add_argument("--demo", action="store_true",
                    help="Gerar relatorio com dados de demo")
    ap.add_argument("--diff", metavar="PREV_JSON",
                    help="Relatorio JSON anterior para modo delta (marca NEW / RECORRENTE)")
    ap.add_argument("--dedup", action="store_true",
                    help="Remover findings duplicados por titulo+categoria")
    ap.add_argument("--sarif", metavar="FILE",
                    help="Exportar tambem em formato SARIF 2.1.0 (CI/CD)")
    ap.add_argument("--json-out", metavar="FILE",
                    help="Exportar findings normalizados em JSON limpo")
    ap.add_argument("--template", choices=["jira", "gitlab"],
                    help="Gerar templates de issue JIRA ou GitLab para cada finding")
    args = ap.parse_args()

    if not args.input and not args.demo:
        ap.print_help()
        sys.exit(1)

    if args.demo:
        print(f"  {C['Y']}[DEMO]{C['X']} Gerando relatorio com dados de exemplo...")
        datasets = make_demo_data()
        args.target = args.target or "demo.example.com"
    else:
        datasets = load_inputs(args.input)
        if not datasets:
            print(f"  {C['R']}[ERRO]{C['X']} Nenhum dado valido carregado.")
            sys.exit(1)

    print(f"\n  {C['G']}[...]{C['X']} Normalizando findings...")
    findings = normalize_findings(datasets)
    print(f"  {C['G']}[OK]{C['X']}  {len(findings)} finding(s) normalizados")

    if args.dedup:
        before = len(findings)
        findings = dedup_findings(findings)
        print(f"  {C['G']}[OK]{C['X']}  Dedup: {before} -> {len(findings)} findings")

    if args.diff:
        findings = apply_diff(findings, args.diff)
        new_cnt = sum(1 for f in findings if f.get("diff_status") == "new")
        rec_cnt = sum(1 for f in findings if f.get("diff_status") == "recurring")
        print(f"  {C['G']}[OK]{C['X']}  Delta: {new_cnt} novos, {rec_cnt} recorrentes")

    target = args.target or (datasets[0].get("target", "") if datasets else "")

    if args.format == "html":
        content = generate_html(findings, args.title, args.author, target)
        out_file = args.output if args.output.endswith(".html") else args.output + ".html"
    else:
        content = generate_markdown(findings, args.title, args.author, target)
        out_file = args.output if args.output.endswith(".md") else args.output + ".md"

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(content)

    if getattr(args, "sarif", None):
        export_sarif(findings, args.sarif)

    if getattr(args, "json_out", None):
        export_json_findings(findings, args.json_out)

    if getattr(args, "template", None):
        tpl_fmt = args.template
        tpl_lines = []
        for fi in findings:
            tpl_lines.append(generate_issue_template(fi, fmt=tpl_fmt))
            tpl_lines.append("\n" + "=" * 60 + "\n")
        tpl_file = f"ghost-report-issues-{tpl_fmt}.md"
        with open(tpl_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(tpl_lines))
        print(f"  {C['G']}[TPL]{C['X']}   Templates {tpl_fmt.upper()} gerados: {tpl_file}")

    counts = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    for fi in findings:
        counts[fi["severity"]] = counts.get(fi["severity"], 0) + 1

    print(f"\n  {C['G']}{'=' * 50}{C['X']}")
    print(f"  {C['N']}Relatorio gerado:{C['X']} {out_file}")
    print(f"  {C['R']}Criticos: {counts[4]}{C['X']}  "
          f"{C['Y']}Altos: {counts[3]}{C['X']}  "
          f"{C['C']}Medios: {counts[2]}{C['X']}  "
          f"{C['G']}Baixos: {counts[1]}{C['X']}")
    print()


if __name__ == "__main__":
    main()
