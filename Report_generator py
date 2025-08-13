"""
Advanced Report Generator for Vulnerability Assessment
Generates comprehensive security reports with professional formatting
"""

import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.severity_scores = {
            "Critical": 9.0,
            "High": 7.0,
            "Medium": 5.0,
            "Low": 3.0
        }
        
        self.severity_emojis = {
            "Critical": "🔴",
            "High": "🟠", 
            "Medium": "🟡",
            "Low": "🔵"
        }
    
    def generate_full_report(self, domain, legacy_results, vuln_results):
        """Generate comprehensive security assessment report"""
        report_sections = []
        
        # Header
        report_sections.append(self._generate_header(domain, vuln_results))
        
        # Executive Summary
        report_sections.append(self._generate_executive_summary(legacy_results, vuln_results))
        
        # Legacy reconnaissance results
        if self._has_legacy_results(legacy_results):
            report_sections.append(self._generate_legacy_section(legacy_results))
        
        # Vulnerability findings
        if vuln_results['vulnerabilities']:
            report_sections.append(self._generate_vulnerability_section(vuln_results))
        
        # Recommendations
        report_sections.append(self._generate_recommendations(vuln_results))
        
        # Footer
        report_sections.append(self._generate_footer())
        
        return "\n\n".join(report_sections)
    
    def generate_dork_report(self, domain, vuln_results):
        """Generate Google dork-focused vulnerability report"""
        report_sections = []
        
        report_sections.append(self._generate_header(domain, vuln_results))
        report_sections.append(self._generate_dork_summary(vuln_results))
        
        if vuln_results['vulnerabilities']:
            report_sections.append(self._generate_vulnerability_section(vuln_results))
        
        report_sections.append(self._generate_recommendations(vuln_results))
        report_sections.append(self._generate_footer())
        
        return "\n\n".join(report_sections)
    
    def generate_quick_report(self, domain, vuln_results):
        """Generate quick scan report"""
        report_sections = []
        
        report_sections.append(f"⚡ *Quick Scan Report for {domain}*")
        report_sections.append(self._generate_quick_summary(vuln_results))
        
        if vuln_results['vulnerabilities']:
            # Show only top 5 most critical findings
            critical_vulns = sorted(
                vuln_results['vulnerabilities'], 
                key=lambda x: self.severity_scores.get(x['severity'], 0), 
                reverse=True
            )[:5]
            
            findings_text = "🔍 *Top Findings:*\n"
            for i, vuln in enumerate(critical_vulns, 1):
                emoji = self.severity_emojis.get(vuln['severity'], '⚪')
                findings_text += f"{i}. {emoji} *{vuln['title']}* ({vuln['severity']})\n"
                findings_text += f"   URL: `{vuln['url']}`\n"
            
            report_sections.append(findings_text.strip())
        
        report_sections.append(f"📊 Run `/dorks {domain}` for detailed analysis")
        
        return "\n\n".join(report_sections)
    
    def _generate_header(self, domain, vuln_results):
        """Generate report header"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        total_vulns = len(vuln_results['vulnerabilities'])
        
        header = f"""🛡️ *SECURITY ASSESSMENT REPORT*
🎯 *Target:* `{domain}`
📅 *Date:* {timestamp}
🔍 *Vulnerabilities Found:* {total_vulns}
🤖 *Scan Type:* Advanced Google Dork Analysis"""
        
        return header
    
    def _generate_executive_summary(self, legacy_results, vuln_results):
        """Generate executive summary"""
        total_vulns = len(vuln_results['vulnerabilities'])
        categories = len(vuln_results['categories_found'])
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vuln_results['vulnerabilities'])
        risk_level = self._get_risk_level(risk_score)
        
        summary = f"""📋 *EXECUTIVE SUMMARY*

🎯 *Assessment Overview:*
• Total Vulnerabilities: {total_vulns}
• Vulnerability Categories: {categories}
• Google Dorks Tested: {vuln_results['total_dorks_tested']}
• Successful Hits: {vuln_results['successful_hits']}

📊 *Risk Assessment:*
• Overall Risk Score: {risk_score:.1f}/10
• Risk Level: *{risk_level}*

🔍 *Reconnaissance Summary:*
• Subdomains Found: {len(legacy_results.get('subdomains', []))}
• Wayback URLs: {len(legacy_results.get('wayback', []))}
• Sitemap Entries: {len(legacy_results.get('sitemap', []))}
• Pastebin Mentions: {len(legacy_results.get('pastebin', []))}"""
        
        return summary
    
    def _generate_dork_summary(self, vuln_results):
        """Generate Google dork scan summary"""
        total_vulns = len(vuln_results['vulnerabilities'])
        
        summary = f"""🔍 *GOOGLE DORK SCAN SUMMARY*

📊 *Scan Statistics:*
• Total Dorks Tested: {vuln_results['total_dorks_tested']}
• Successful Hits: {vuln_results['successful_hits']}
• Vulnerabilities Found: {total_vulns}
• Categories Affected: {len(vuln_results['categories_found'])}

🎯 *Categories Found:*
{self._format_categories_list(vuln_results['categories_found'])}"""
        
        return summary
    
    def _generate_quick_summary(self, vuln_results):
        """Generate quick scan summary"""
        total_vulns = len(vuln_results['vulnerabilities'])
        risk_score = self._calculate_risk_score(vuln_results['vulnerabilities'])
        
        summary = f"""📊 *Scan Results:*
• Vulnerabilities: {total_vulns}
• Risk Score: {risk_score:.1f}/10
• Categories: {len(vuln_results['categories_found'])}"""
        
        return summary
    
    def _generate_legacy_section(self, legacy_results):
        """Generate legacy reconnaissance section"""
        sections = ["🔍 *RECONNAISSANCE FINDINGS*"]
        
        if legacy_results.get('subdomains'):
            subdomains = legacy_results['subdomains'][:10]  # Limit display
            sections.append(f"🌐 *Subdomains ({len(legacy_results['subdomains'])} total):*")
            for subdomain in subdomains:
                sections.append(f"• `{subdomain}`")
            if len(legacy_results['subdomains']) > 10:
                sections.append(f"... and {len(legacy_results['subdomains']) - 10} more")
        
        if legacy_results.get('wayback'):
            sections.append(f"\n⏰ *Wayback URLs:* {len(legacy_results['wayback'])} historical URLs found")
        
        if legacy_results.get('sitemap'):
            sections.append(f"🗺️ *Sitemap URLs:* {len(legacy_results['sitemap'])} URLs discovered")
        
        if legacy_results.get('pastebin'):
            sections.append(f"📄 *Pastebin:* {len(legacy_results['pastebin'])} mentions found")
        
        return "\n".join(sections)
    
    def _generate_vulnerability_section(self, vuln_results):
        """Generate detailed vulnerability findings"""
        if not vuln_results['vulnerabilities']:
            return ""
        
        # Group by severity
        vulns_by_severity = {}
        for vuln in vuln_results['vulnerabilities']:
            severity = vuln['severity']
            if severity not in vulns_by_severity:
                vulns_by_severity[severity] = []
            vulns_by_severity[severity].append(vuln)
        
        sections = ["🚨 *VULNERABILITY FINDINGS*"]
        
        # Process in severity order
        for severity in ["Critical", "High", "Medium", "Low"]:
            if severity in vulns_by_severity:
                emoji = self.severity_emojis[severity]
                vulns = vulns_by_severity[severity]
                sections.append(f"\n{emoji} *{severity} Severity ({len(vulns)} findings)*")
                
                for i, vuln in enumerate(vulns, 1):
                    sections.append(f"\n*{i}. {vuln['title']}*")
                    sections.append(f"🔗 URL: `{vuln['url']}`")
                    sections.append(f"📝 Description: {vuln['description']}")
                    sections.append(f"🎯 Evidence: {vuln['evidence']}")
                    sections.append(f"🔍 Dork: `{vuln['dork_query']}`")
                    sections.append(f"📊 Confidence: {int(vuln['confidence'] * 100)}%")
                    
                    if i < len(vulns):
                        sections.append("─" * 40)
        
        return "\n".join(sections)
    
    def _generate_recommendations(self, vuln_results):
        """Generate security recommendations"""
        recommendations = ["🔧 *SECURITY RECOMMENDATIONS*"]
        
        if not vuln_results['vulnerabilities']:
            recommendations.append("✅ No immediate vulnerabilities found through Google dorking.")
            recommendations.append("🔍 Continue regular security assessments and monitoring.")
            return "\n".join(recommendations)
        
        # Category-based recommendations
        categories_found = set(vuln['category'] for vuln in vuln_results['vulnerabilities'])
        
        rec_mapping = {
            "sql_injection": "• Implement parameterized queries and input validation\n• Use WAF to filter malicious requests\n• Regular security code reviews",
            "xss_vulnerabilities": "• Implement proper output encoding\n• Use Content Security Policy (CSP)\n• Validate and sanitize all user inputs",
            "local_file_inclusion": "• Restrict file system access\n• Validate file paths and names\n• Use whitelist approach for file access",
            "exposed_files": "• Remove sensitive files from web directories\n• Implement proper access controls\n• Regular file system audits",
            "admin_panels": "• Implement strong authentication\n• Use IP whitelisting for admin access\n• Enable multi-factor authentication",
            "directory_listing": "• Disable directory listing in web server config\n• Use proper index files\n• Implement access controls"
        }
        
        for category in categories_found:
            if category in rec_mapping:
                recommendations.append(f"\n*{category.replace('_', ' ').title()}:*")
                recommendations.append(rec_mapping[category])
        
        # General recommendations
        recommendations.append("\n*General Security Measures:*")
        recommendations.append("• Regular penetration testing")
        recommendations.append("• Implement security monitoring")
        recommendations.append("• Keep all software updated")
        recommendations.append("• Security awareness training")
        
        return "\n".join(recommendations)
    
    def _generate_footer(self):
        """Generate report footer"""
        return """─────────────────────────────
⚠️ *DISCLAIMER:* This report is for authorized security testing only.
🔒 *Bot Version:* Advanced Recon Bot v2.0
📞 *Support:* Use /help for assistance"""
    
    def _calculate_risk_score(self, vulnerabilities):
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0
        for vuln in vulnerabilities:
            severity_score = self.severity_scores.get(vuln['severity'], 1.0)
            confidence = vuln.get('confidence', 0.5)
            total_score += severity_score * confidence
        
        # Normalize to 0-10 scale
        max_possible = len(vulnerabilities) * 9.0  # Max critical severity
        if max_possible > 0:
            normalized_score = (total_score / max_possible) * 10
            return min(normalized_score, 10.0)
        
        return 0.0
    
    def _get_risk_level(self, risk_score):
        """Get risk level from score"""
        if risk_score >= 8.0:
            return "🔴 CRITICAL"
        elif risk_score >= 6.0:
            return "🟠 HIGH" 
        elif risk_score >= 4.0:
            return "🟡 MEDIUM"
        elif risk_score >= 2.0:
            return "🔵 LOW"
        else:
            return "🟢 MINIMAL"
    
    def _format_categories_list(self, categories):
        """Format categories list"""
        if not categories:
            return "• No categories found"
        
        formatted = []
        for category in categories:
            formatted.append(f"• {category.replace('_', ' ').title()}")
        
        return "\n".join(formatted)
    
    def _has_legacy_results(self, legacy_results):
        """Check if legacy results contain data"""
        return any(
            legacy_results.get(key, []) 
            for key in ['subdomains', 'wayback', 'sitemap', 'pastebin']
        )
