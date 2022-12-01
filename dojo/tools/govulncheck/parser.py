import json
from itertools import groupby
from itertools import islice
from dojo.models import Finding

SEVERITY = 'Info'


class GovulncheckParser:

    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    @staticmethod
    def get_location(data, node):
        call = data['Calls']['Functions'][str(node)]['CallSites'][0]['Pos']
        return f"{call['Filename']}:{str(call['Line'])}:{str(call['Column'])}"

    def get_findings(self, scan_file, test):

        findings = []

        # get data from report.json
        scan_data = scan_file.read()
        # remove intro from developer
        scan_data = scan_data[scan_data.find(b'{'):]
        data = json.loads(scan_data)

        list_vulns = data['Vulns']

        for cve, elems in groupby(list_vulns, key=lambda vuln: vuln['OSV']['aliases'][0]):
            first_elem = list(islice(elems, 1))
            title = first_elem[0]['OSV']['id']
            description = first_elem[0]['OSV']['details']
            references = first_elem[0]['OSV']['references'][0]['url']
            url = first_elem[0]['OSV']['affected'][0]['database_specific']['url']
            vuln_methods = set()
            impact = set()
            for elem in elems:
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
