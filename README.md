# LLM NVD Search
This project utilises an OpenAI API key to interface with GPT 3.5 and subsequently search the NVD database using natural language.

## Example Usage:
```
python3 working_final.py "What vulnerabilities exist for Apache ActiveMQ Artemis?"
```
Lists all vulnerabilities for the detected product.


```
python3 working_final.py "What medium vulnerabilities exist for Apache ActiveMQ Artemis?"
```
Lists all vulnerabilities of the detected severity for the detected product.

```
python3 working_final.py "What medium vulnerabilities exist for Apache ActiveMQ Artemis? Provide CVEs published between 1st August 2022 and 1st September 2022."
```
Lists all vulnerabilities of the detected severity for the detected product. Filters between the two dates provided (NVD limit is a max span of 120 days).

```
python3 working_final.py "What medium vulnerabilities exist for Apache ActiveMQ Artemis? Provide CVEs published between 1st August 2022 and 1st September 2022. Extra details"
```
Same as above but also brings back supplemental details from cvedetails.com (requires an API key).

API keys should be configured in `.env`

## Stateful Example - Work in Progress!

```
python3 stateful.py "What vulnerabilities exist for Apache ActiveMQ Artemis?"
```
Allows a follow-up response or responses, e.g. `filter range - January 2022 to March 2022`. Doesn't work with any other filters as yet.
