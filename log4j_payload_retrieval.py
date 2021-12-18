import ldap
import argparse
import csv

def parse_input_file(rel_path_to_file):
	all_results = []

	with open(rel_path_to_file, 'r') as infile:
		for ldap_url in infile:
			print (f"[+] Processing LDAP URL: {ldap_url}")
			if validate_ldap_url(ldap_url.strip()):
				results_dict = get_ldap_response(ldap_url.strip())
				all_results.append(results_dict)
			else:
				print (f'[+] NOT A VALID LDAP URL. SKIPPING THIS ENTRY: \n\t{ldap_url}')
	infile.close()


	return all_results

'''
Validation checks performed:
	- starts with ldap://
'''
def validate_ldap_url(ldap_url):
	ldap_url = ldap_url.lower()
	if not ldap_url.startswith("ldap://"):
		return False

	return True

def get_ldap_response(ldap_url):
	try:
		ldap_server, search_base = ldap_url.rsplit('/', 1)
		conn = ldap.initialize(ldap_server)
		conn.simple_bind() #this is where we get exception if it's not an ldap server
		results = conn.search(search_base, 0)
		while results:
			res_type, res_data = conn.result()
			if res_data:
				results_dict = parse_res_data(res_data, ldap_url, search_base)
				if results_dict:
					return results_dict
			results -= 1
			
	except Exception as e:
		error_args = handle_ldap_error(e)
		results_dict = {
			"ldap_url": ldap_url,
			"verdict": error_args['tldr'],
			"error_desc": error_args['desc'],
			"error_info": error_args['info'],
			"response_data": None,
			"payload_url": None
			}
		return results_dict

def parse_res_data(res_data, ldap_url, search_base):
	try:
		response_data = res_data[0]
		
		if (len(response_data) == 2 and response_data[0] == search_base 
			and ("javaCodeBase" in response_data[1] and "javaFactory" in response_data[1])):
			dn = response_data[0]
			data = response_data[1]
			java_codebase = data['javaCodeBase'][0].decode("utf-8")
			java_factory = data['javaFactory'][0].decode("utf-8")
			results_dict = {
				"ldap_url": ldap_url,
				"verdict": "SUCCESS",
				"error_desc": None,
				"error_info": None,
				"response_data": data,
				"payload_url": java_codebase + java_factory + ".class"
				}
			return results_dict
	
	except Exception as e:
		print (e)
		return False
	
	return None

def handle_ldap_error(error):
	if error.args[0] == 0 and error.args[1] == "Error":
		return {"tldr": "LDAP CONNECTION FAILED", "desc":"Error 0", "info":"This error doesn't have info attached, but the destination likely returned data in some unexpected format."}

	if error.args and error.args[0].get('desc', None) and error.args[0].get('info', None):
		desc = error.args[0].get('desc', None)
		info = error.args[0].get('info', None)

		if desc == "Can't contact LDAP server":
			# print (f"[+] LDAP Connection FAILED -- Destination is not an LDAP server or it is unreachable.")
			# print (f"[+] Error Description: {desc}")
			# print (f"[+] Error Info: {info}")

			return {"tldr": "LDAP CONNECTION FAILED", "desc":desc, "info":info}

		if desc == "Invalid DN syntax":
			# print (f"[+] LDAP Connection FAILED -- The destination is an LDAP server, but the search base term was invalid. The DN is likely no longer in use.")
			# print (f"[+] Error Description: {desc}")
			# print (f"[+] Error Info: {info}")
			return {"tldr": "LDAP CONNECTION FAILED", "desc":desc, "info":info}

		else:
			# print (f"[+] The LDAP connection failed, but I'm not sure why. Please consult the error message below for more info.")
			# print (f"[+] Error Description: {desc}")
			# print (f"[+] Error Info: {info}")
			# print (f"[+] Full Error Args: {error.args[0]}")
			return {"tldr": "LDAP CONNECTION FAILED", "desc":desc, "info":info}
	else:
		# print (f"Error message was structured in an unexpected way. Please consult the error message below for more info.")
		# print (f"[+] Full Error Args: {error}")
		return {"tldr": "UNKOWN ERROR", "desc":None, "info":None}

def write_output_file(filename, results_list):
	outpath = "./output/" + filename
	with open(outpath, mode='w') as outfile:
		csv_writer = csv.writer(outfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		csv_writer.writerow([
			"ldap_url", 
			"valid redirect",
			"payload url",
			"response.javaClassName", 
			"response.javaCodeBase", 
			"response.objectClass", 
			"response.javaFactory",
			"error.description",
			"error.info"
			])
		for result in results_list:
			if result.get("verdict", None) == "SUCCESS":
				data = result['response_data']
				csv_writer.writerow([
					result['ldap_url'],
					result['verdict'],
					result['payload_url'],
					data['javaClassName'][0].decode("utf-8"),
					data['javaCodeBase'][0].decode("utf-8"),
					data['objectClass'][0].decode("utf-8"),
					data['javaFactory'][0].decode("utf-8"),
					"None",
					"None"
					])
			else:
				csv_writer.writerow([
					result['ldap_url'],
					result['verdict'], 
					"None",
					"None",
					"None",
					"None",
					"None",
					result['error_desc'],
					result['error_info']
					])

	outfile.close()

def main():
	#set up arg parser
	parser = argparse.ArgumentParser()

	#set up args
	group = parser.add_mutually_exclusive_group()
	group.add_argument('--input_file', type=str) #look up all URLs in a text file (1 URL per line), mututally exclusive with --url
	group.add_argument('--url', type=str) #look up a single LDAP url, mututally exclusive with --csv
	parser.add_argument('--out', type=str) #output file name. results will be written to ./output/filename

	#parse the args
	args = parser.parse_args()
	
	if args.input_file:
		results_list = parse_input_file(args.input_file) #CHANGE
		if args.out:
			print (f"[+] Writing results to {args.out}")
			write_output_file(args.out, results_list)
			print (f"[+] Done.")

		else:
			for results_dict in results_list:
				if results_dict['verdict'] == "INVALID LDAP":
					print (f"[+] INVALID RESPONSE FROM {results_dict['ldap_url']}")
					print (f"{results_dict}")
				else:
					print (f"[+] LDAP URL: {results_dict['ldap_url']}")
					print (f"[+] LDAP RESPONSE: {results_dict['verdict']}")
					print (f"[+] LDAP RESPONSE DATA: \n\t{results_dict['response_data']}")
					print (f"[+] PAYLOAD URL: {results_dict['payload_url']}")
					print ("\n\n\n")

	elif args.url:
		results_dict = get_ldap_response(args.url)
		if args.out:
			print (f"[+] Writing results to {args.out}")
			write_output_file(args.out, [results_dict])
			print (f"[+] Done.")
		else:
			if results_dict['verdict'] != "SUCCESS":
					print (f"[+] INVALID RESPONSE FROM {results_dict['ldap_url']}")
					print (results_dict)
			else:
				print (f"[+] LDAP URL: {results_dict['ldap_url']}")
				print (f"[+] LDAP RESPONSE: {results_dict['verdict']}")
				print (f"[+] LDAP RESPONSE DATA: \n\t{results_dict['response_data']}")
				print (f"[+] PAYLOAD URL: {results_dict['payload_url']}")

	else:
		print ("[+] NO ARGS SUPPLIED - Using test input and output...")
		results_list = parse_input_file("test_input.txt")
		print (f"[+] Writing results to testing2.csv")
		write_output_file("testing2.csv", results_list)
		print (f"[+] Done.")

if __name__ == '__main__':
	main()