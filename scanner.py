#! /usr/bin/env python

# Actual Scanner Implementation

import requests
import re
import urlparse
from bs4 import BeautifulSoup

class Scanner:
	def __init__(self,url,ignore):
		self.target_url = url
		self.target_links = []
		self.session = requests.Session()
		self.ignore_list = ignore

	def extract_links(self,target_url):
		response = self.session.get(target_url)
		return re.findall('(?:href=")(.*?)"',response.content)

	def crawl(self,target_url = None):
		if target_url == None:
			target_url = self.target_url
		all_links = self.extract_links(target_url)
		for link in all_links:
			link = urlparse.urljoin(target_url,link)

			if "#" in link:
				link = link.split("#")[0]

			if self.target_url in link and link not in self.target_links and link not in self.ignore_list:
				self.target_links.append(link)
				print(link)
				self.crawl(link)

	def extract_forms(self,url):
		response = self.session.get(url)
		parsed_html = BeautifulSoup(response.content,features="lxml")
		return parsed_html.findAll("form")

	def submit_form(self,form,value,url):
		action = form.get("action")
		post_url = urlparse.urljoin(url,action)
		method = form.get("method")
		input_list = form.findAll("input")
		post_dict = {}
		for inp in input_list:
			name = inp.get("name")
			input_type = inp.get("type")
			input_val = inp.get("value")
			if input_type == "text":
				input_val = value
			post_dict[name] = input_val

		if method == "post":	
			return self.session.post(post_url,data=post_dict)
		else:
			return self.session.get(post_url,params=post_dict)

	def run_scanner(self):
		for link in self.target_links:
			forms = self.extract_forms(link)
			for form in forms:
				print("[+] Form found in the link " + link)
				is_vul = self.test_xss_in_form(form,link)
				if is_vul:
					print("\n\n[++] XSS Vulnerability in the link " + link + "with form ")
					print(form)

			if "=" in link:
				print("[+] Testing " + link)
				is_vul = self.test_xss_in_link(link)
				if is_vul:
					print("\n\n[++] XSS Vulnerability in the link " + link)

	def test_xss_in_form(self,form,url):
		xss_script = "<scRipt>alert('Hello')</Script>"
		response = self.submit_form(form,xss_script,url)
		return xss_script in response.content

	def test_xss_in_link(self,url):
		xss_script = "<scRipt>alert('Hello')</Script>"
		url = url.replace("=","=" + xss_script)
		response = self.session.get(url)
		return xss_script in response.content