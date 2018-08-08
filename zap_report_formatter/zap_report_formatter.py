from io import BytesIO
import xml.etree.ElementTree as ET
import collections, sys, json, re
Alert = collections.namedtuple('Alert', ['name', 'description', 'solution', 'target', 'raw_results'])
whitelist_json = {}

def read_json_from_file(path):
    return json.load(open(path))

def is_whitelisted(plugin_id, uri):
    if plugin_id in whitelist_json:
        for whitelist_uri in whitelist_json[plugin_id]['regex_uris']:
            if re.match(whitelist_uri, uri):
                return True
        
    return False

def parse_json_report(json_obj, whitelist_json):
    alerts = {}
    fields_to_remove = ('confidence', 'wascid', 'sourceid', 'riskcode', 'cweid', 'otherinfo')

    # if there is only one site, zap will not return a list, need to make it a list
    if not isinstance(json_obj['site'], list):
        json_obj['site'] = [json_obj['site']]

    for site in json_obj['site']:
        for alertitem in site['alerts']:

            desc = alertitem.pop('desc')
            solution = alertitem.pop('solution')

            # Remove redundant information
            for key in fields_to_remove:
                if key in alertitem:
                    del alertitem[key]
            
            # Remove whitelisted alerts
            alertitem['instances'] = [i for i in alertitem['instances'] \
                if not is_whitelisted(alertitem['pluginid'], i['uri'])]
            if not alertitem['instances']:
                continue
                
            alert = Alert(
                alertitem['name'],
                desc,
                solution,
                site['@name'],
                json.dumps(alertitem, sort_keys=True, indent=2, separators=(',', ': '))
            )
            alerts.setdefault(alertitem['pluginid'], []).append(alert)
    return alerts

def generate_junit_xml(alerts):
    junit_xml = ET.Element('testsuites')
    junit_xml.set('id', 'zap.security.scan')
    for plugin_id in alerts:
        testsuite = ET.SubElement(junit_xml, 'testsuite')
        testsuite.set('id', plugin_id)
        testsuite.set('name', alerts[plugin_id][0].name)
        for alert in alerts[plugin_id]:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', alert.target)
            failure = ET.SubElement(testcase, 'failure')
            failure.set('message', 'Problem:\n' + alert.description + \
                '\n\nSolution:\n' + alert.solution)
            failure.text = alert.raw_results
    return junit_xml

def write_to_file(xml, filename):
    f = BytesIO()
    et = ET.ElementTree(xml)
    et.write(f, encoding='utf-8', xml_declaration=True)
    outfile = open(filename, 'w')
    outfile.write(f.getvalue())
    outfile.close

def format(input, whitelist, output):
    json_report = read_json_from_file(input)
    global whitelist_json
    whitelist_json = read_json_from_file(whitelist)

    alerts = parse_json_report(json_report, whitelist_json)
    junit_xml = generate_junit_xml(alerts)
    write_to_file(junit_xml, filename=output)
