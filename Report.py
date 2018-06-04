'''
# Programmer: Brent E. Chambers
# Date: 07/24/2017  #Almost DefCon time baby!
# Filename: Report.py
# Description: ~!~ Summer of Code ~!~ Almost out baby! WCOBust!
	Generic html report generator for the AIC_Ops module.
	Can't do work until you report work! haha
'''
import LandScape

ls = LandScape.Targets()
ls.load_targets()

html_header = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="generator" content="CoffeeCup HTML Editor (www.coffeecup.com)">
    <meta name="dcterms.created" content="Tue, 25 Jul 2017 00:05:37 GMT">
    <meta name="description" content="">
    <meta name="keywords" content="">
    <title></title>
    
    <style type="text/css">
    <!--
    body {
      color:#000000;
      background-color:#FFFFFF;
      background-image:url('Background Image');
      background-repeat:no-repeat;
    }
    a  { color:#0000FF; }
    a:visited { color:#800080; }
    a:hover { color:#008000; }
    a:active { color:#FF0000; }
    -->
    </style>
    <!--[if IE]>
    <script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>
    <![endif]-->
  </head>
  <body>
  """

report_header = """
  <h2>Adversarial Engagement Report: Penetration Test</h3>
<b> Presented To: </b> Cygiene Solutions LLC<br>
<b> Date: </b> July 27, 2017 <br>
<b> Testing Team: </b> Security Operations <br><br>
<hr>
"""

executive_summary = """
<h3> Executive Summary </h3>
[Insert Executive_Summary]
<br>
<br>
<br>
<br>
<br>
<br>
<hr>
"""

landscape_and_analysis = """
<h3> Landscape Summary and Analysis </h3>
[Insert Landscape Summary Content]
<br>
<br>
<br>
<br>
<br>
<br>
<hr>
"""


summary_of_findings = """
<h3> Summary of Findings </h3>
[Insert Landscape Summary Content]
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<hr>
"""


host_report = """<hr>
<b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; IP Address: </b> 69.55.48.63

<h4>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [!] Attack Landscape:</h4>
<b>
<br>
<br>
<br>
<h4>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [!] Initial Analysis:</h4>
<b>
<br>
<br>
<br>
<h4>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [!] Attack Plan:</h4>
<b>
<br>
<br>
<br>
<h4>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [!] Results:</h4>
<b>
<br>
<br>
<br>
<hr>
"""


recommendations = """
<b> Recommendations </b>
<br>
<br>
<br>
<hr>
"""

conclusion = """
<b> Conclusion </b>
<br>
<br>
<br>
<hr>
"""

html_footer = "</body></html>"


## Build the file

full_report = ""
full_report += html_header
full_report += report_header
full_report += executive_summary
full_report += landscape_and_analysis
full_report += summary_of_findings
full_report += host_report
ip_profile = ''
for ip in ls.Lookup.keys():
	for line in ls.Lookup[ip][0]:
		ip_profile += (line + "<br>")

ip_attack_surface= ''
count = len(self.Lookup[host])
for ip in ls.Lookup.keys():
	count = len(self.Lookup[ip])
	for line in ls.Lookup[ip][1:count]
		for i in line:
			ip_attack_surface += (i + "<br>")
	
full_report += recommendations
full_report += conclusion
full_report += html_footer

## Write the file

mainpage = open('aic_report.html', 'w')
mainpage.write(full_report)
mainpage.close()



