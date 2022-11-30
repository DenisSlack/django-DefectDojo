import json
from itertools import groupby
from dojo.models import Finding

SEVERITY = 'Info'


class GovulncheckParser:

    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    def get_location(self, data, node):
        call = data['Calls']['Functions'][str(node)]
        location = f"{call['CallSites'][0]['Pos']['Filename']}:{str(call['CallSites'][0]['Pos']['Line'])}:" \
                   f"{str(call['CallSites'][0]['Pos']['Column'])}"
        return location

    def get_findings(self, scan_file, test):

        findings = []

        # get data from report.json
        scan_data = scan_file.read()
        # remove intro from developer
        scan_data = scan_data[scan_data.find(b'{'):]
        data = json.loads(scan_data)

        list_vulns = data['Vulns']

        for cve, elems in groupby(list_vulns, key=lambda vuln: vuln['OSV']['aliases'][0]):
            collected = False
            vuln_methods = set()
            impact = set()
            title = str()
            description = str()
            references = str()
            url = str()
            for elem in elems:
                if not collected:
                    title = elem['OSV']['id']
                    description = elem['OSV']['details']
                    references = elem['OSV']['references'][0]['url']
                    url = elem['OSV']['affected'][0]['database_specific']['url']
                    collected = True
                impact.add(self.get_location(data, elem['CallSink']))
                vuln_methods.update(elem['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])

            findings.append(Finding(
                title=title,
                cve=cve,
                references=references,
                description=description,
                url=url,
                impact='\n'.join(impact),
                severity=SEVERITY,
                component_name='; '.join(vuln_methods)
            ))
        return findings
