#!/usr/bin/env python3

import requests
import ipaddress
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

print(Fore.CYAN + "=" * 60)
print(Fore.CYAN + "         THREAT INTEL IP ANALYZER")
print(Fore.CYAN + "=" * 60)

ip = input(Fore.YELLOW + "\n[+] Ingresa una IP para analizar: ")

print(Fore.BLUE + "\n[+] Consultando informacion...\n")

try:

    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.is_private:

        print(Fore.GREEN + "[!] La IP pertenece a un rango privado.")
        print(Fore.GREEN + "[!] Clasificacion : PRIVATE")
        print(Fore.GREEN + "[!] Riesgo        : LOW")

    else:

        response = requests.get(f"http://ip-api.com/json/{ip}")

        data = response.json()

        country = data.get('country')
        region = data.get('regionName')
        city = data.get('city')
        isp = data.get('isp')
        org = data.get('org')
        asn = data.get('as')
        timezone = data.get('timezone')

        risk = "LOW"

        suspicious_keywords = [
            "hosting",
            "vpn",
            "proxy",
            "cloud",
            "digitalocean",
            "amazon",
            "microsoft"
        ]

        org_check = str(org).lower()

        if any(word in org_check for word in suspicious_keywords):
            risk = "MEDIUM"

        report = {
            "ip": ip,
            "country": country,
            "region": region,
            "city": city,
            "isp": isp,
            "organization": org,
            "asn": asn,
            "timezone": timezone,
            "risk": risk,
            "timestamp": str(datetime.now())
        }

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        json_file = f"reports/report_{timestamp}.json"

        with open(json_file, "w") as file:
            json.dump(report, file, indent=4)

        html_file = f"html_reports/report_{timestamp}.html"

        html_content = f"""
        <html>
        <head>
            <title>Threat Intel Report</title>
        </head>
        <body>
            <h1>Threat Intelligence Report</h1>
            <hr>
            <p><b>IP:</b> {ip}</p>
            <p><b>Country:</b> {country}</p>
            <p><b>Region:</b> {region}</p>
            <p><b>City:</b> {city}</p>
            <p><b>ISP:</b> {isp}</p>
            <p><b>Organization:</b> {org}</p>
            <p><b>ASN:</b> {asn}</p>
            <p><b>Timezone:</b> {timezone}</p>
            <p><b>Risk:</b> {risk}</p>
        </body>
        </html>
        """

        with open(html_file, "w") as file:
            file.write(html_content)

        print(Fore.CYAN + "=" * 60)
        print(Fore.CYAN + "                 REPORTE")
        print(Fore.CYAN + "=" * 60)

        print(Fore.GREEN + f"\n[+] IP Analizada   : {ip}")
        print(Fore.GREEN + f"[+] Pais           : {country}")
        print(Fore.GREEN + f"[+] Region         : {region}")
        print(Fore.GREEN + f"[+] Ciudad         : {city}")
        print(Fore.GREEN + f"[+] ISP            : {isp}")
        print(Fore.GREEN + f"[+] Organizacion   : {org}")
        print(Fore.GREEN + f"[+] ASN            : {asn}")
        print(Fore.GREEN + f"[+] Timezone       : {timezone}")

        print(Fore.YELLOW + f"\n[+] Clasificacion  : PUBLIC IP")
        print(Fore.YELLOW + f"[+] Riesgo Inicial : {risk}")

        print(Fore.BLUE + f"\n[+] Reporte JSON:")
        print(Fore.BLUE + f"    {json_file}")

        print(Fore.BLUE + f"\n[+] Reporte HTML:")
        print(Fore.BLUE + f"    {html_file}")

        print(Fore.CYAN + "\n[+] Analisis completado.")

except ValueError:

    print(Fore.RED + "\n[!] La IP ingresada no es valida.")

except Exception as e:

    print(Fore.RED + f"\n[!] Error: {e}")
