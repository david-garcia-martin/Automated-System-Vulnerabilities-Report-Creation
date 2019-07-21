# -*- coding: utf-8 -*-
#!/usr/bin/env python
import sys, os, csv, re
import numpy as np
import matplotlib.pyplot as plt
from docxtpl import DocxTemplate, InlineImage
import pandas as pd

MONTHS = ["","January", "February", "March","April","May","June","July","August","September","October","November","December"]
tpl = DocxTemplate('template.docx')
context = {
    'day': '',
    'month': '',
    'year': '',
    'Windows': '',
    'Ubuntu': '',
    'MacOS': '',
    'Total': '',
    'count_High': '',
    'count_Medium': '',
    'count_Low': '',
    'count_Critical': '',
    'col_dangerous': ["OS", "CVE", "Date", "CVSS", "Summary" ],
    'tbl_dangerous': [],
    'col_labels': [ "", "Critical", "High", "Medium", "Low"],
    'tbl_contents1': [],
    'col_asset_labels': [""],
    'tbl_contents2': [],
    'pieChart': '',
    'assetsT': '',
    'assetsVuln': '',
    'assets10': '',
    'assets20': '',
    'assets30': '',
    'assets31': '',
    'control': '',
    'control1': '',
    'data': '',
    'data1': '',
    'assets': [],
    'OS1': '',
    'OS2': '',
    'OS3': '',
    'OS1_name': '',
    'OS2_name': '',
    'OS3_name': '',
    'OS1_CIA': '',
    'OS2_CIA': '',
    'OS3_CIA': ''

}
results_summary_operating_system={}
results_dangerous_vulnerability = []

def get_summary_count(file):
    sys.stdout.write("\nGETTING SUMMARY COUNT...")
    count_Critical,count_High,count_Medium,count_Low =0,0,0,0
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=';')
        line_count = 0
        for row in csv_reader:
            if line_count>=1:
                operating_system = row[0]
                cve = row[1]
                date = row[2]
                cvss = float(row[6])
                summary=row[11]
                if cvss>=9.0 and cvss<=10.0:
                    if (operating_system not in results_summary_operating_system):
                        aux = [1,0,0,0]
                        results_summary_operating_system[operating_system] = aux
                        if cvss==10.0:
                            results_dangerous_vulnerability.append(operating_system)
                            results_dangerous_vulnerability.append(cve)
                            results_dangerous_vulnerability.append(date)
                            results_dangerous_vulnerability.append(cvss)
                            results_dangerous_vulnerability.append(summary)
                    else:
                        aux[0]+=1
                        results_summary_operating_system[operating_system] = aux
                        if cvss==10.0:
                            results_dangerous_vulnerability.append(operating_system)
                            results_dangerous_vulnerability.append(cve)
                            results_dangerous_vulnerability.append(date)
                            results_dangerous_vulnerability.append(cvss)
                            results_dangerous_vulnerability.append(summary)
                    count_Critical+=1
                elif cvss>=7.0 and cvss<=8.9:
                    if operating_system not in results_summary_operating_system:
                        aux = [0, 1, 0, 0]
                        results_summary_operating_system[operating_system] = aux
                    else:
                        aux[1] += 1
                        results_summary_operating_system[operating_system] = aux
                    count_High+=1
                elif cvss >= 4.0 and cvss <= 6.9:
                    if operating_system not in results_summary_operating_system:
                        aux = [0, 0, 1, 0]
                        results_summary_operating_system[operating_system] = aux
                    else:
                        aux[2] += 1
                        results_summary_operating_system[operating_system] = aux
                    count_Medium+=1
                else:
                    if operating_system not in results_summary_operating_system:
                        aux = [0, 0, 0, 1]
                        results_summary_operating_system[operating_system] = aux
                    else:
                        aux[3] += 1
                        results_summary_operating_system[operating_system] = aux
                    count_Low+=1
            line_count += 1

    results_summary_operating_system["Total"] = [count_Critical, count_High,count_Medium, count_Low]

    sys.stdout.write("OK!")
    get_summary_operating_system()

def get_summary_operating_system():
    sys.stdout.write("\nGETTING SUMMARY OPERATING SYSTEM...")

    # REPORT insert summary
    n=0
    for key,value in results_summary_operating_system.items():
        context['tbl_contents1'].append({'cols': [str(key), str(value[0]),str(value[1]),str(value[2]),str(value[3])]})
        pie_chart_operating_system(key, value,n)
        n+=1

    sys.stdout.write("OK!")

def get_asset_inventory(file):
    sys.stdout.write("\nGETTING INVENTORY REPORT...");
    operating_system_dict ={}
    total=0
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=';')
        line_count=0
        for row in csv_reader:
            if line_count>=1:
                operating_system=row[0]
                if operating_system not in operating_system_dict:
                    operating_system_dict[operating_system]=1
                else:
                    operating_system_dict[operating_system]+=1
            line_count += 1

    for value in operating_system_dict.values():
        total+=value
    operating_system_dict["Total"]=total

    # REPORT insert inventory report
    context['col_asset_labels'].clear()
    for key,value in operating_system_dict.items():
        context['col_asset_labels'].append(key)
        context['tbl_contents2'].append(str(value))
    sys.stdout.write("OK!")

    generate_pie_chart(operating_system_dict)

def get_assets_dangerous_vulnerability():
    sys.stdout.write("\nGETTING MOST DANGEROUS VULNERABILITY REPORT...");

    for i in range(1, len(results_dangerous_vulnerability)):
        if i%5==0 and i!=0:
            context['tbl_dangerous'].append({'cols': [results_dangerous_vulnerability[i-5],results_dangerous_vulnerability[i-4],results_dangerous_vulnerability[i-3],results_dangerous_vulnerability[i-2],results_dangerous_vulnerability[i-1]]})
    sys.stdout.write("OK!")

def generate_pie_chart(operating_dict):
    fig, ax = plt.subplots(figsize=(6,3), subplot_kw=dict(aspect="equal"))
    operating_system,data = [],[]
    for key,value in operating_dict.items():
        if key != "Total":
            operating_system.append(str(key)+"-"+str(value))
            data.append(value)
        else:
            total = value
    wedges, texts = ax.pie(data, wedgeprops=dict(width=0.5), startangle=-40)

    bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
    kw = dict(xycoords='data', textcoords='data', arrowprops=dict(arrowstyle="-"),
              bbox=bbox_props, zorder=0, va="center")

    for i, p in enumerate(wedges):
        ang = (p.theta2 - p.theta1) / 2. + p.theta1
        y = np.sin(np.deg2rad(ang))
        x = np.cos(np.deg2rad(ang))
        horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
        connectionstyle = "angle,angleA=0,angleB={}".format(ang)
        kw["arrowprops"].update({"connectionstyle": connectionstyle})
        ax.annotate(operating_system[i], xy=(x, y), xytext=(1.35 * np.sign(x), 1.4 * y),
                    horizontalalignment=horizontalalignment, **kw)

    ax.set_title("Total number of vulnerabilities: "+str(total))

    plt.savefig("pieChart_total.png")
    context['pieChart'] = InlineImage(tpl, 'pieChart_total.png')

def pie_chart_operating_system(operating, value,n):
    labels = 'Critical', 'High', 'Medium', 'Low'
    sizes = [value[0], value[1], value[2],value[3]]
    colors = ['#ff0000', '#FF8000', '#FFDC00', '#00C1FF']

    fig, ax = plt.subplots(figsize=(6, 3), subplot_kw=dict(aspect="equal"))

    def func(pct, allvals):
        absolute = int(pct / 100. * np.sum(allvals))
        if absolute!=0:
            return "{:.1f}%\n({:d})".format(pct, absolute)
    wedges, texts, autotexts = ax.pie(sizes, autopct=lambda pct: func(pct, sizes), textprops=dict(color="w"), colors=colors)
    ax.legend(wedges, labels, title="CVSS", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    plt.setp(autotexts, size=8, weight="bold")
    ax.set_title("Vulnerabilities affecting " + operating)
    plt.savefig("pieChart_" + operating + ".png")

    if n==0:
        context['OS1'] = InlineImage(tpl, "pieChart_"+operating+".png")
        context['OS1_name'] = str(operating)
    elif n==1:
        context['OS2'] = InlineImage(tpl, "pieChart_"+operating+".png")
        context['OS2_name'] = str(operating)
    elif n==2:
        context['OS3'] = InlineImage(tpl, "pieChart_"+operating+".png")
        context['OS3_name'] = str(operating)

def get_CIA_operating_system(file):
    sys.stdout.write("\nGETTING CIA OPERATING SYSTEM...")
    results_CIA = {}
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=';')
        line_count = 0
        for row in csv_reader:
            if line_count >= 1:
                operating_system = row[0]
                confidentiality = row [9]
                integrity = row [10]
                availability = row[8]
                if confidentiality=="COMPLETE":
                    if (operating_system not in results_CIA):
                        aux = [1,0,0,0,0,0,0,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[0] += 1
                        results_CIA[operating_system] = aux
                elif confidentiality== "PARTIAL":
                    if (operating_system not in results_CIA):
                        aux = [0,1,0,0,0,0,0,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[1] += 1
                        results_CIA[operating_system] = aux
                elif confidentiality == "NONE":
                    if (operating_system not in results_CIA):
                        aux = [0,0,1,0,0,0,0,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[2] += 1
                        results_CIA[operating_system] = aux
                if integrity=="COMPLETE":
                    if (operating_system not in results_CIA):
                        aux = [0,0,0,1,0,0,0,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[3] += 1
                        results_CIA[operating_system] = aux
                elif integrity== "PARTIAL":
                    if (operating_system not in results_CIA):
                        aux = [0,0,0,0,1,0,0,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[4] += 1
                        results_CIA[operating_system] = aux
                elif integrity == "NONE":
                    if (operating_system not in results_CIA):
                        aux = [0,0,0,0,0,1,0,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[5] += 1
                        results_CIA[operating_system] = aux
                if availability=="COMPLETE":
                    if (operating_system not in results_CIA):
                        aux = [0,0,0,0,0,0,1,0,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[6] += 1
                        results_CIA[operating_system] = aux
                elif availability== "PARTIAL":
                    if (operating_system not in results_CIA):
                        aux = [0,0,0,0,0,0,0,1,0]
                        results_CIA[operating_system] = aux
                    else:
                        aux[7] += 1
                        results_CIA[operating_system] = aux
                elif availability == "NONE":
                    if (operating_system not in results_CIA):
                        aux = [0,0,0,0,0,0,0,0,1]
                        results_CIA[operating_system] = aux
                    else:
                        aux[8] += 1
                        results_CIA[operating_system] = aux
            line_count += 1

    n = 0
    for key, value in results_CIA.items():
        generate_bar_chartCIA(key, value, n)
        n += 1
    sys.stdout.write("OK!")

def generate_bar_chartCIA (operating, value, n):
    data, aux = [],[]
    colors = ['#FF0F00', '#FFEC00', '#00FF51']

    for i in range(1, len(value)+1):
        aux.append(value[i-1])
        if i%3==0:
            data.append(aux)
            aux=[]

    df = pd.DataFrame(data, columns=['Total','Partial','None'], index= ['Confidentiality', 'Integrity', 'Availability'])
    df.hist()
    df.plot.bar(rot=0, color=colors)

    plt.savefig("pieChart_CIA_" + operating + ".png")

    if n==0:
        context['OS1_CIA'] = InlineImage(tpl, "pieChart_CIA_"+operating+".png")
    elif n==1:
        context['OS2_CIA'] = InlineImage(tpl, "pieChart_CIA_"+operating+".png")
    elif n==2:
        context['OS3_CIA'] = InlineImage(tpl, "pieChart_CIA_"+operating+".png")

def create_report(file,timestamp):

    # retrieve summary count
    get_summary_count(file)

    # retrieve asset inventory and generate chart
    get_asset_inventory(file)

    # retrieve most dangerous vulnerabilities
    get_assets_dangerous_vulnerability()

    # retrieve CIA information per operating system
    get_CIA_operating_system(file)

    context["day"] = timestamp[:2]
    for i in range(1,len(MONTHS)):
        if int(timestamp[4:5]) == i:
            context["month"] = MONTHS[i]
    context["year"] = timestamp[-4:]
    tpl.render(context)

    tpl.save("report_" + timestamp + ".docx")
    os.remove('pieChart_total.png')
    for operating in results_summary_operating_system.keys():
        if operating!="Total":
            os.remove("pieChart_"+operating+".png")
            os.remove("pieChart_CIA_" + operating + ".png")

    sys.stdout.write("\n\nREPORT SUCCESSFULLY GENERATED! :)")

