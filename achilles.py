#!/usr/bin/env python3
#Tilfoejer vores shebang så vi kan gøre vores script eksekverbart, vha. ./achilles.py istedet for python3 achilles.py

import argparse
import requests
import validators
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup   #Godt staerkt open source library, der kan bruges til at parsning af dokumenter
from bs4 import Comment

parser = argparse.ArgumentParser(description="The Achilles HTML Vulnerability analyzer Version 1.0")

                                                        #Laekker mulighed vi får fra argparse
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze.")
parser.add_argument('--config', help='Path to configuration file.')
parser.add_argument('-o', '--output', help='Report file output path.')

args=parser.parse_args()

config={'forms':True, 'comments':True, 'passwords':True}
if(args.config):
    print('Using config file: ' + args.config)
    config_file = open(args.config, 'r')
    config_from_file = yaml.safe_load(config_file)#Der bruges i video yaml.load, men ved mig spoerger den efter 2 argumenter, som den ikke goer i video, saa bruger i stedet safe_load, som jeg laeste om på pyyaml siden.
    if(config_from_file):
        #(linjen blev fjernet)Hvis der er en config file, så er vores config lige den, ellers gaar vi bare efter alt true som sat oppe på linje 22
        config = { **config, **config_from_file}# ** betyder expand this out to a full dictionary, og altsaa hvor at vi her merger vores 2 config sammen
report=''

url=args.url

if(validators.url(url)):
    result_html     = requests.get(url).text

    parsed_html     = BeautifulSoup(result_html, 'html.parser')#vi spoerger python at kalde vores BSoup constructor om at parse vores html fra vores result_html string

    forms           = (parsed_html.find_all('form'))#Kan her vaere alt, og behoever ikke vaere en form, men kan f.eks. vaere h1 el., og faar saa vist hvad form her f.eks. indeholder. Dette kommer til at vaere vores basis for vores analyse.

    comments        = parsed_html.find_all(string=lambda text:isinstance(text,Comment))#Text er her fra klassen Comment 

    password_inputs = parsed_html.find_all('input', {'name' : 'password'})#Tjekker efter typen af input, i form af password her
    if(config['forms']): #Koer kun koden hvis config forms =true
        for form in forms:
            if((form.get('action').find('https')< 0) and (urlparse(url).scheme != 'https')):#hvis vores form/url, ikke er en https, saa er dens security
                report+= 'Form Issue: Insecure form action ' + form.get('action') + ' found in document\n'

    if(config['comments']):
        for comment in comments: 
            if(comment.find('key') >-1):
                report+= 'Comment Issue: Key is found in the HTML document comments, please remove\n'
    if(config['passwords']):
        for password_input in password_inputs:
            if(password_input.get('type')!='password'):
                report+='Input Issue: Plaintext password input was found. Please change to password type input\n'
else: 
    print('Invalid URL. Please include full URL, including scheme.')

if(report==''):
    report+='Nice job. Your HTML document is secure!\n'
else:
    header='Vulnerability report is as follows: \n'
    header+='===============================================\n\n'
    report= header + report
     
print(report)

if(args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print('Report saved to: ' + args.output)