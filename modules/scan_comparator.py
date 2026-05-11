"""
Scan Comparison Engine for Vulnix
Security Drift Detection - Compare two scans and track security evolution
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict


class ScanComparator:
    """Compare deux scans et détecte les changements de sécurité"""
    
    SEVERITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }
    
    SEVERITY_POINTS = {
        "CRITICAL": 25,
        "HIGH": 16,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1,
    }
    
    def __init__(self, scan1: Dict, scan2: Dict, scan1_meta: Dict = None, scan2_meta: Dict = None):
        """
        Args:
            scan1: Premier scan (avant correction)
            scan2: Deuxième scan (après correction)
            scan1_meta: Métadonnées du premier scan (date, type, etc.)
            scan2_meta: Métadonnées du deuxième scan
        """
        self.scan1 = scan1
        self.scan2 = scan2
        self.scan1_meta = scan1_meta or {}
        self.scan2_meta = scan2_meta or {}
        
        self.vulns1 = self._extract_vulnerabilities(scan1)
        self.vulns2 = self._extract_vulnerabilities(scan2)
        self.ports1 = self._extract_ports(scan1)
        self.ports2 = self._extract_ports(scan2)
        
    def _extract_vulnerabilities(self, scan: Dict) -> Dict[str, Dict]:
        """Extrait toutes les vulnérabilités d'un scan"""
        vulns = {}
        
        # Pour security scan
        findings = scan.get("findings", [])
        for finding in findings:
            vuln_id = self._get_finding_id(finding)
            if vuln_id:
                vulns[vuln_id] = {
                    "id": vuln_id,
                    "title": finding.get("name", finding.get("title", "")),
                    "severity": finding.get("severity", "INFO").upper(),
                    "description": finding.get("detail", finding.get("description", "")),
                    "remediation": finding.get("recommendation", ""),
                    "evidence": finding.get("evidence", ""),
                    "category": finding.get("category", "Finding"),
                    "port": finding.get("metadata", {}).get("port"),
                    "service": finding.get("metadata", {}).get("service"),
                }
        
        # Pour scanned_items
        for item in scan.get("scanned_items", []):
            vuln_id = item.get("title", "")
            if vuln_id and vuln_id not in vulns:
                vulns[vuln_id] = {
                    "id": vuln_id,
                    "title": item.get("title", ""),
                    "severity": item.get("severity", "INFO").upper(),
                    "description": item.get("description", ""),
                    "remediation": item.get("recommendation", ""),
                    "evidence": item.get("evidence", ""),
                    "category": item.get("category", "Finding"),
                    "port": None,
                    "service": None,
                }
        
        # Pour CVEs dans les ports
        for port in scan.get("open_ports", []):
            for cve in port.get("cves", []):
                cve_id = cve.get("id", cve.get("cve", ""))
                if cve_id:
                    vulns[cve_id] = {
                        "id": cve_id,
                        "title": cve_id,
                        "severity": cve.get("severity", "INFO").upper(),
                        "description": cve.get("description", ""),
                        "remediation": port.get("recommendation", "Patch the affected service"),
                        "evidence": f"Port {port.get('port')} - {port.get('service')}",
                        "category": "CVE",
                        "port": port.get("port"),
                        "service": port.get("service"),
                    }
        
        return vulns
    
    def _get_finding_id(self, finding: Dict) -> str:
        """Génère un ID unique pour un finding"""
        name = finding.get("name", finding.get("title", ""))
        asset = finding.get("asset", "")
        if name and asset:
            return f"{name}__{asset}"
        return name or finding.get("detail", "")[:50]
    
    def _extract_ports(self, scan: Dict) -> Dict[int, Dict]:
        """Extrait les ports ouverts d'un scan"""
        ports = {}
        
        for port in scan.get("open_ports", []):
            port_num = port.get("port")
            if port_num:
                ports[port_num] = {
                    "port": port_num,
                    "protocol": port.get("protocol", "tcp"),
                    "service": port.get("service", "unknown"),
                    "product": port.get("product", ""),
                    "version": port.get("version", ""),
                    "severity": port.get("severity", "INFO"),
                    "cve_count": port.get("cve_count", 0),
                }
        
        return ports
    
    def compare(self) -> Dict:
        """Compare les deux scans et retourne l'évolution complète"""
        
        vulns1_ids = set(self.vulns1.keys())
        vulns2_ids = set(self.vulns2.keys())
        
        # Catégories principales
        fixed = vulns1_ids - vulns2_ids
        new = vulns2_ids - vulns1_ids
        persistent = vulns1_ids & vulns2_ids
        
        # Analyse des sévérités
        fixed_by_severity = self._count_by_severity({k: self.vulns1[k] for k in fixed})
        new_by_severity = self._count_by_severity({k: self.vulns2[k] for k in new})
        persistent_by_severity = self._count_by_severity({k: self.vulns2[k] for k in persistent})
        
        # Régressions (sévérité augmentée)
        regressions = self._detect_regressions(persistent)
        
        # Améliorations (sévérité diminuée)
        improvements = self._detect_improvements(persistent)
        
        # Calcul des scores
        score1 = self._calculate_security_score(self.vulns1)
        score2 = self._calculate_security_score(self.vulns2)
        score_change = score2 - score1
        
        # Analyse des ports
        ports_added, ports_removed = self._compare_ports()
        
        # Trend analysis
        trend = self._generate_trend_analysis(len(fixed), len(new), len(persistent), score_change)
        
        # Recommandations
        recommendations = self._generate_recommendations(
            len(fixed), len(new), len(persistent), regressions, score_change
        )
        
        return {
            "summary": {
                "fixed": len(fixed),
                "new": len(new),
                "persistent": len(persistent),
                "total_before": len(vulns1_ids),
                "total_after": len(vulns2_ids),
                "score_before": score1,
                "score_after": score2,
                "score_change": score_change,
                "improvement_percent": round((score_change / max(score1, 1)) * 100, 1),
                "comparison_date": datetime.utcnow().isoformat(),
                "days_between": self._days_between(),
            },
            "by_severity": {
                "fixed": fixed_by_severity,
                "new": new_by_severity,
                "persistent": persistent_by_severity
            },
            "ports": {
                "added": ports_added,
                "removed": ports_removed,
                "added_count": len(ports_added),
                "removed_count": len(ports_removed),
            },
            "details": {
                "fixed_vulnerabilities": [
                    {
                        "id": vuln_id,
                        "title": self.vulns1[vuln_id]["title"],
                        "severity": self.vulns1[vuln_id]["severity"],
                        "category": self.vulns1[vuln_id].get("category", ""),
                        "remediation": self.vulns1[vuln_id].get("remediation", ""),
                    }
                    for vuln_id in sorted(fixed)
                ][:100],
                "new_vulnerabilities": [
                    {
                        "id": vuln_id,
                        "title": self.vulns2[vuln_id]["title"],
                        "severity": self.vulns2[vuln_id]["severity"],
                        "category": self.vulns2[vuln_id].get("category", ""),
                        "remediation": self.vulns2[vuln_id].get("remediation", ""),
                    }
                    for vuln_id in sorted(new)
                ][:100],
                "persistent_vulnerabilities": [
                    {
                        "id": vuln_id,
                        "title": self.vulns2[vuln_id]["title"],
                        "severity": self.vulns2[vuln_id]["severity"],
                        "category": self.vulns2[vuln_id].get("category", ""),
                    }
                    for vuln_id in sorted(persistent)
                ][:100],
                "regressions": regressions,
                "improvements": improvements,
            },
            "trend": trend,
            "recommendations": recommendations,
        }
    
    def _count_by_severity(self, vulns: Dict) -> Dict[str, int]:
        """Compte les vulnérabilités par sévérité"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in vulns.values():
            severity = vuln.get("severity", "INFO").upper()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _calculate_security_score(self, vulns: Dict) -> int:
        """Calcule un score de sécurité de 0 à 100 (100 = parfait)"""
        if not vulns:
            return 100
        
        total_penalty = 0
        for vuln in vulns.values():
            severity = vuln.get("severity", "INFO").upper()
            penalty = self.SEVERITY_POINTS.get(severity, 1)
            total_penalty += penalty
        
        # Formule: 100 - (penalty / (max_penalty * sqrt(n)))
        max_possible = len(vulns) * 25
        if max_possible == 0:
            return 100
        
        raw_score = 100 - (total_penalty / max_possible * 100)
        return max(0, min(100, int(raw_score)))
    
    def _detect_regressions(self, persistent: set) -> List[Dict]:
        """Détecte les vulnérabilités dont la sévérité a augmenté"""
        regressions = []
        for vuln_id in persistent:
            sev1 = self.vulns1[vuln_id].get("severity", "INFO").upper()
            sev2 = self.vulns2[vuln_id].get("severity", "INFO").upper()
            
            if self.SEVERITY_ORDER[sev2] < self.SEVERITY_ORDER[sev1]:  # Pire
                regressions.append({
                    "id": vuln_id,
                    "title": self.vulns2[vuln_id]["title"],
                    "severity_before": sev1,
                    "severity_after": sev2,
                    "warning": f"Séverité augmentée de {sev1} à {sev2}",
                })
        return regressions
    
    def _detect_improvements(self, persistent: set) -> List[Dict]:
        """Détecte les vulnérabilités dont la sévérité a diminué"""
        improvements = []
        for vuln_id in persistent:
            sev1 = self.vulns1[vuln_id].get("severity", "INFO").upper()
            sev2 = self.vulns2[vuln_id].get("severity", "INFO").upper()
            
            if self.SEVERITY_ORDER[sev2] > self.SEVERITY_ORDER[sev1]:  # Mieux
                improvements.append({
                    "id": vuln_id,
                    "title": self.vulns2[vuln_id]["title"],
                    "severity_before": sev1,
                    "severity_after": sev2,
                    "message": f"Séverité diminuée de {sev1} à {sev2}",
                })
        return improvements
    
    def _compare_ports(self) -> Tuple[List[Dict], List[Dict]]:
        """Compare les ports ouverts entre les deux scans"""
        ports1_ids = set(self.ports1.keys())
        ports2_ids = set(self.ports2.keys())
        
        added = [self.ports2[p] for p in (ports2_ids - ports1_ids)]
        removed = [self.ports1[p] for p in (ports1_ids - ports2_ids)]
        
        return added, removed
    
    def _days_between(self) -> int:
        """Calcule le nombre de jours entre les deux scans"""
        try:
            date1_str = self.scan1_meta.get("created_at", "")
            date2_str = self.scan2_meta.get("created_at", "")
            
            if date1_str and date2_str:
                date1 = datetime.fromisoformat(date1_str[:19])
                date2 = datetime.fromisoformat(date2_str[:19])
                return abs((date2 - date1).days)
        except:
            pass
        return 0
    
    def _generate_trend_analysis(self, fixed: int, new: int, persistent: int, score_change: int) -> Dict:
        """Génère une analyse de tendance"""
        if fixed > new:
            if score_change > 10:
                trend = "IMPROVING_RAPID"
                message = f"🚀 Excellente progression ! {fixed} vulnérabilités corrigées, {new} nouvelles."
                icon = "📈🚀"
            else:
                trend = "IMPROVING"
                message = f"✅ Sécurité en amélioration. {fixed} fixes vs {new} nouvelles vulns."
                icon = "📈"
        elif new > fixed:
            if new - fixed > 10:
                trend = "DEGRADING_RAPID"
                message = f"⚠️ Alerte ! {new} nouvelles vulnérabilités détectées, seulement {fixed} corrigées."
                icon = "📉⚠️"
            else:
                trend = "DEGRADING"
                message = f"⚠️ Sécurité en dégradation. {new} nouvelles vulns apparues."
                icon = "📉"
        else:
            if persistent > 0:
                trend = "STAGNANT"
                message = f"➡️ Situation stable mais {persistent} vulns persistentes non corrigées."
                icon = "➡️"
            else:
                trend = "CLEAN"
                message = "✨ Plus aucune vulnérabilité détectée ! Parfait !"
                icon = "🏆"
        
        return {
            "trend": trend,
            "message": message,
            "icon": icon,
            "trend_color": self._get_trend_color(trend),
        }
    
    def _get_trend_color(self, trend: str) -> str:
        colors = {
            "IMPROVING_RAPID": "#10b981",
            "IMPROVING": "#22c55e",
            "STAGNANT": "#f59e0b",
            "DEGRADING": "#ef4444",
            "DEGRADING_RAPID": "#dc2626",
            "CLEAN": "#06b6d4",
        }
        return colors.get(trend, "#6b7280")
    
    def _generate_recommendations(self, fixed: int, new: int, persistent: int, 
                                   regressions: list, score_change: int) -> List[str]:
        """Génère des recommandations basées sur la comparaison"""
        recs = []
        
        if persistent > 0:
            recs.append(f"🔴 {persistent} vulnérabilités persistent : priorisez leur correction")
        
        if regressions:
            recs.append(f"⚠️ {len(regressions)} vulnérabilités ont empiré : investiguez immédiatement")
        
        if new > 0:
            recs.append(f"🆕 {new} nouvelles vulnérabilités : analysez leur impact")
        
        if score_change < 0:
            recs.append("📉 Le score de sécurité a baissé : revoyez les changements récents")
        elif score_change > 20:
            recs.append("🏆 Excellente amélioration ! Continuez sur cette lancée")
        
        if fixed == 0 and new == 0 and persistent > 0:
            recs.append("➡️ Aucune évolution : planifiez correctives pour les vulns persistantes")
        
        return recs[:5]


def format_comparison_for_display(comparison: Dict) -> Dict:
    """Formate la comparaison pour l'affichage dans le template"""
    summary = comparison["summary"]
    trend = comparison["trend"]
    
    return {
        "summary": {
            "fixed": summary["fixed"],
            "new": summary["new"],
            "persistent": summary["persistent"],
            "fixed_percent": round(summary["fixed"] / max(summary["total_before"], 1) * 100, 1),
            "score_before": summary["score_before"],
            "score_after": summary["score_after"],
            "score_change": summary["score_change"],
            "improvement_percent": summary["improvement_percent"],
        },
        "trend": trend,
        "by_severity": comparison["by_severity"],
        "top_fixed": comparison["details"]["fixed_vulnerabilities"][:5],
        "top_new": comparison["details"]["new_vulnerabilities"][:5],
        "recommendations": comparison["recommendations"],
    }