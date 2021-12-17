# LogradorRetriever

## Setup

Clone the repo locally.

Initialize the virtualenv.
`source venv/bin/activate`

## Usage

Use a txt file of LDAP URLs to test and output the results to out.csv:
`python3 log4j_payload_retrieval.py --input_file test_input.csv --out out.csv`

Supply a single LDAP URL to test (prints output in console):
`python3 log4j_payload_retrieval.py --url ldap://<IP or DOMAIN>:1389/bttjx2`
