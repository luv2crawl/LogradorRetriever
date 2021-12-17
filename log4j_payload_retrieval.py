import ldap
import argparse
import csv

'''
e.g.
>>> get_ldap_stage2('ldap://66.228.33.31:443/fh4als')
'http://66.228.33.31:80/ExecTemplateJDK7.class'
'''

def get_ldap_stage2(ldap_url):
	out_dict = {"ldap_url":ldap_url, "verdict":"INVALID LDAP"}
	try:
		ldap_server, search_base = ldap_url.rsplit('/', 1)
		conn = ldap.initialize(ldap_server)
		conn.simple_bind()
		results = conn.search(search_base, 0)
		while results:
			res_type, res_data = conn.result()
			if res_data:
				out_dict['response_data'] = res_data
				for res in res_data:
					if len(res) != 2 or res[0] != search_base:
						continue
					res = res[1]
					if 'javaCodeBase' not in res and 'javaFactory' not in res:
						#print(f'Unexpected response: {res_data}')
						out_dict['payload_url'] = None
					class_url = res['javaCodeBase'][0] + res['javaFactory'][0] + b'.class'
					out_dict['payload_url'] = class_url.decode()
					out_dict['verdict'] = "VALID LDAP RESPONSE (GOT REDIRECT)"
			results -= 1
	except Exception as e:
		print(f'[+] LDAP Error: {e}')
	return out_dict

def parse_input_file(rel_path_to_file):
	all_results = []

	try:
		with open(rel_path_to_file, 'r') as infile:
			for ldap_url in infile:
				if validate_ldap_url(ldap_url):
					results_dict = get_ldap_stage2(ldap_url.strip())
					all_results.append(results_dict)
				else:
					print (f'[+] NOT A VALID LDAP URL. SKIPPING THIS ENTRY: \n\t{ldap_url}')
		infile.close()

	except Exception as e:
		print (f'[+] Error while reading input file: {e}')

	return all_results

def validate_ldap_url(ldap_url):
	return True

def write_output_file(rel_path_to_file, results_list):
	with open(rel_path_to_file, mode='w') as outfile:
		csv_writer = csv.writer(outfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		csv_writer.writerow([
			"ldap_url", 
			"valid redirect", 
			"response.javaClassName", 
			"response.javaCodeBase", 
			"response.objectClass", 
			"response.javaFactory",
			"payload url"
			])
		for result in results_list:
			response_data = result['response_data'][0][1]
			csv_writer.writerow([
				result['ldap_url'],
				result['verdict'], 
				response_data['javaClassName'][0].decode("utf-8"),
				response_data['javaCodeBase'][0].decode("utf-8"),
				response_data['objectClass'][0].decode("utf-8"),
				response_data['javaFactory'][0].decode("utf-8"),
				result['payload_url']
				])

	outfile.close()

def main():
	#set up arg parser
	parser = argparse.ArgumentParser()

	#set up args
	group = parser.add_mutually_exclusive_group()
	group.add_argument('--input_file', type=str) #look up all URLs in a text file (1 URL per line), mututally exclusive with --url
	group.add_argument('--url', type=str) #look up a single LDAP url, mututally exclusive with --csv
	parser.add_argument('--out', type=str) #relative path to output file (include file name)

	#parse the args
	args = parser.parse_args()
	
	if args.input_file:
		results_list = parse_input_file(args.input_file)
		if args.out:
			print (f"[+] Writing results to {args.out}")
			write_output_file(args.out, results_list)
			print (f"[+] Done.")

		else:
			for results_dict in results_list:
				print (f"[+] LDAP URL: {results_dict['ldap_url']}")
				print (f"[+] LDAP RESPONSE: {results_dict['verdict']}")
				print (f"[+] LDAP RESPONSE DATA: \n\t{results_dict['response_data'][0][1]}")
				print (f"[+] PAYLOAD URL: {results_dict['payload_url']}")
				print ("\n\n\n")

	elif args.url:
		results_dict = get_ldap_stage2(args.url)
		print (f"[+] LDAP URL: {results_dict['ldap_url']}")
		print (f"[+] LDAP RESPONSE: {results_dict['verdict']}")
		print (f"[+] LDAP RESPONSE DATA: \n\t{results_dict['response_data'][0][1]}")
		print (f"[+] PAYLOAD URL: {results_dict['payload_url']}")

	else:
		print("NO ARGS YOU DUMB IDIOT!!")

if __name__ == '__main__':
	main()