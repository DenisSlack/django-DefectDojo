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
        calls = [x for x in data['Calls']['Functions'][str(node)]['CallSites'] if x['Parent'] == 1]
        return list(map(lambda x: f"{x['Pos']['Filename']}:{str(x['Pos']['Line'])}:{str(x['Pos']['Column'])}",
                        calls))

    def get_findings(self, scan_file, test):

        findings = []

        # get data from report.json
        scan_data = scan_file.read()
        # remove intro from developer
        scan_data = scan_data[scan_data.find(b'{'):]
        data = json.loads(scan_data)

        if data is None:
            return findings

        list_vulns = data['Vulns']

        for cve, elems in groupby(list_vulns, key=lambda vuln: vuln['OSV']['aliases'][0]):
            first_elem = list(islice(elems, 1))
            title = first_elem[0]['OSV']['id']
            component = first_elem[0]["PkgPath"]
            references = first_elem[0]['OSV']['references'][0]['url']
            url = first_elem[0]['OSV']['affected'][0]['database_specific']['url']
            vuln_methods = set(first_elem[0]['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])
            impact = set(self.get_location(data, first_elem[0]['CallSink']))
            for elem in elems:
                impact.update(self.get_location(data, elem['CallSink']))
                vuln_methods.update(elem['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])
            findings.append(Finding(
                title=title,
                cve=cve,
                references=references,
                description=f"Vulnerable functions: {'; '.join(vuln_methods)}",
                url=url,
                impact='; '.join(impact) if impact else "In your code no call of these vulnerable function, " \
                                                        "but they be in call stack of other function",
                severity=SEVERITY,
                component_name=component
            ))
        return findings
