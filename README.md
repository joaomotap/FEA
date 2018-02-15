# FEA - Forensics Enhanced Analysis

by João Mota (2017) jm@void.software

Report module for the Autopsy Forensic Analysis platform, developed in Jython, within
the scope of the Computer Science Degree of the Escola Superior de Tecnologia e Gestão do
Instituto Politécnico de Leiria, Portugal.

FEA comprises three separate report modules for the Autopsy digital forensics platform:

	i) for email filtering and validation
	ii) for credit card number validation and
	iii) for Bitcoin wallet addresses and private key search and validation.





## FEA@Autopsy

Forensics Enhanced Analysis



João Eduardo Lisboa Da Mota Parreira

Work developed under the guidance and coordination of Professors Patrício Domingues and Miguel Frade


### Abstract

Three distinct Autopsy modules were developed with different purposes, but with similar approaches. Primarily, the new modules aim to improve existing features, such as the email and credit card number search capabilities of the platform which are built-in to one of the default ingestion modules, and secondly, to incorporate new features which can take further advantage from the insights gained, namely by adding Bitcoin wallet address and private key search and validation processes.


### FEA Development approach

After careful consideration of the goals of this project and the framework provided by Autopsy, it was decided that report modules coupled with custom keyword lists in the Keyword Search ingest module would incorporate the most adequate approach, with multiple advantages:

- Standard ingest modules are optimized in the way they tackle the task of doing the actual ingestion, and relying on them will ensure that this work will in the future take advantage of any updates that may be introduced by the community to that basic functionality.
- Existing cases with processed data will not have to re-run the time-consuming ingestion process.
- The separation of scope means that the ingest stage does not have to be further burdened with resource-intensive tasks, allowing the investigator to cherry-pick the most relevant artifacts and types of analysis to be submitted to the report modules developed for the abovementioned specific purposes.
- Automatic creation of multiple reports in file formats that facilitate further manual processing (such as Microsoft Excel workbooks).

Therefore, three separate Jython scripts were developed, each with a configuration panel built in Java Swing, for analysis of email addresses, credit card account numbers and bitcoin keys and addresses.

All of the modules were developed and tested with Autopsy for Windows version 4.3.0, dated July 19, 2016, version 4.4.0, dated May 30, 2017 and version 4.4.1, dated Aug 9, 2017.

#### Email Report Module

The goal of this report module is to perform additional validation of the strings captured as emails by the Keyword Search ingestion module, which puts results into the Blackboard as artifacts containing the attribute TSK\_SET\_NAME with the value "Email Addresses".

TSK's API allows us to retrieve every artifact generated during ingestion, and then iterate through each of its attributes to retrieve the actual email address strings, which are stored as type TSK\_KEYWORD.

After identifying each relevant string, the following validations are (optionally) performed:

1.
  1. Top Level Domain (TLD) Validation

This validation pertains to the last part of the domain name of an email address (e.g. COM in the case of _google.com_).

The official TLD database is maintained by IANA, the Internet Assigned Numbers Authority, through its "Root Zone Database"&quot;", and it includes the standard EDU, COM, NET, ORG, GOV, MIL and INT identifiers, country TLDs that incorporate a two-character code corresponding to the ISO-3166 standard.

The implemented software resorts to scraping the website to retrieve valid TLDs, since there is no public API or any such service available for doing so that could be found. This relies on the list made public on https://data.iana.org/TLD/tlds-alpha-by-domain.txt, and which is updated on a daily basis. This list is retrieved just before the start of the artifacts processing algorithm, and each time the module is ran, in order to ensure that the latest version is being used.

After the list is made available, each string is iterated to verify if the substring after the last dot character (".") matches any of its entries, and classifying artifacts accordingly, by marking as false positives any addresses with invalid TLDs. Any addresses that fail the TLD verification will not undergo further verifications, since they can already be safely classified as false positives, beyond any reasonable doubt.

1.
  2. Alphanumeric syntax check

One of the simplest email address validation procedures that the Keyword Search ingest module overlooks is verifying whether the strings contain only alphanumeric characters, as per the rules for email address syntax defined in RFC5322, duly adjusted to the most common current implementation.

The report module implements the validation by crosschecking every domain against the appropriate regular expression:

##### ^[\_a-z0-9-]+(\.[\_a-z0-9-]+)\*@[a-z0-9-]+(\.[a-z0-9-]+)\*(\.[a-z]{2,4})

1.
  3. Domain name validation

If the user choses to do so in the module configuration settings - which is optional due to the resource-intensive nature of this task - a Domain Name Server (DNS) lookup is performed for the domain portion of each email address (following the "@"), after discarding duplicate entries.

Since the lookup request is a blocking process, an asynchronous multi-threaded approach was applied, and the user can further decide on the number of simultaneous threads to be made available to the process, according to preference or available resources, via the Java Swing configuration panel presented before running the module. Therefore, a decision can be made on whether to privilege fast execution with a larger volume of simultaneous DNS requests, or instead, to have slower execution but with a reduced impact on the service. In any case, it should be noted that simultaneous requests to the DNS service are frequent in many applications (e.g., web browsers), without posing a problem from the perspective of service availability, which in the case of DNS, is known to be quite scalable.

Each thread will launch a domain lookup task that relies on the java.net standard Java Development Kit (JDK) library to perform the lookup request, and returning results to the thread queue structure3.

1.
  4. Internet Archive validation

The fact that a DNS lookup currently returns an inexistent domain does not necessarily mean that it was not once in existence. Domain name registrations are valid for a limited amount of time, and in case they are not renewed by their respective owner, or acquired by someone else, they cease to exist.

One way around this obstacle would be to search for the domain name being investigated in DNS registration history. However, there are two key limitations to this option: i) existing services do not support all of the currently valid TLDs, and ii) such services are not freely available, and using them would restrict FEA's usage and adoption.

The Wayback Machine or Internet Archive on the other hand, is a non-profit library with the self-proclaimed mission of providing Universal Access to All Knowledge, that makes available 20+ years of web history. Considering it hosts data referring to about 279 billion webpages, it was considered to be of interest to give users the option to further verify email domains against this vast database, and thus assess if these were ever registered in the past – and provide some insight on the content they might have been serving. Even though the Wayback Machine is certainly not a comprehensive list of every website ever made, it undoubtedly contains sufficient data to make it an interesting resource within the scope of this project.

Conveniently, the Wayback Machine provides an API to facilitate queries to its records, returning a JSON object containing details on every snapshot available at the archive for any given domain address, including a timestamp referring to its date of inclusion.

The module thus queries the Wayback Machine API for every domain address that failed the DNS lookup validation, and stores a link to the last version ever seen online according to the archive, if available, adding it to the final report. The queries are performed in sequence, with no option for multithreaded processing, in order to avoid flooding the service with requests.

Within the scope of a typical forensic analysis, the assessment of past existence of a domain is of particular interest, since it is quite frequent that malicious activity is based on servers running on domains registered specifically for that purpose, to be discarded shortly after. Nevertheless, there is no guarantee that Internet Archive records are exhaustive, for a number of reasons: i) the service might not have had time to index domains that existed for brief periods of time, ii) the service's web crawler prioritizes websites according to its own ranking system, based on popularity and number of times the target showed up on searches, and thus might not index websites that have been online for longer periods, and iii) the owners of the website(s) might have explicitly requested to not have the website indexed by crawlers, either directly to the Wayback Machine, or via installation of a robots.txt flag, which is a universal technical standard (called the SRE – standard for robot exclusion) for indicating a preference to not have a website crawled, and which the Internet Archive abides by.

Finally, it should be further noted that even if a given domain name is referenced by the Internet Archive, that does not prove that the email address actually existed, since there is no guarantee that the domain was used for email services.

1.
  5. Reported data

Depending on user preference, one or two files can be added to Autopsy's collection of reports containing the output of the module, and which includes, for each email address found by the Keyword Search ingest module, the following status information:

- Alphanumeric check
- TLD check
- DNS Lookup verification
- Wayback Machine / Internet Archive lookup
- Distinct valid domain names and number of occurrences (hits)

If the user has so decided in the report configuration dialog box, an Excel Workbook is generated with two distinct sub sheets containing this information, and which can be used for further filtering and processing.  This process relies on the xlwt pure Python open source package library, which is in turn based on the pyExcelerator package. Regardless of opting to generate an Excel report, a CSV file with the module's results is always added to Autopsy's reports list.

#### Credit Card Accounts Report Module

A separate module was developed exclusively for addressing investigation of credit card numbers present in the forensic data source. Like it does for email addresses, Autopsy also provides a list of potential credit card numbers. The approach is similar to the previous module, and the Keyword Search module is used for obtaining the credit card numbers, which in terms of ingestion differ only in the attribute type added to the result set of artifacts (TSK\_ACCOUNT), and the attribute type of the string value with the actual numbers (TSK\_CARD\_NUMBER).

As for the validation, a Luhn algorithm is ran to perform a checksum on each number. Also known as the "modulus 10" or "mod 10" algorithm, it provides a simple validation mechanism that works by appending a check digit to the end of a partial account number to generate the full account number, that must pass a verification test:

- --From the rightmost digit, which is the check digit, and moving left, double the value of every second digit. If the result of this doubling operation is greater than 9 (e.g., 8 × 2 = 16), then add the digits of the product (e.g., 16: 1 + 6 = 7, 18: 1 + 8 = 9) or alternatively subtract 9 from the product (e.g., 16: 16 - 9 = 7, 18: 18 - 9 = 9).
- --Take the sum of all the digits.
- --If the total ends in zero, then the number is valid according to the Luhn formula.

This process is widely used for validation of credit card numbers, and specified in ISO/IEC 7812-1, with the main purpose of protecting against accidental errors, but which serves the current purpose of rapidly identifying false positives.

It is known that the algorithm if flawed with a transposition error, since transposing digits 09 for 90 cannot be detected, and therefore it cannot be relied upon for an absolute validation of the account numbers. Nevertheless, for the purposes of improving validation of false positives, it is an enhancement of the core features of Autopsy, and will contribute for enhancing data quality and reduce time needed for analysis.

#### Bitcoin Addresses and Keys Report Module

One other increasingly interesting type of artifact to be recovered from digital forensics analysis case files are those connected with cryptocurrencies, considering these are often associated with potentially malicious actions, or at least worthy of further investigation. Recent high profile and fast spreading ransomware making use of the anonymity provided by these potential payment gateways are a perfect example of the high interest in locating traces of Bitcoin addresses or even private keys that may be stored in the available data sources.

Currently, Autopsy does not support any built-in tools to facilitate the discovery of such artifacts, however the Keyword Search module can again be put to use, by creating custom lists with regular expressions to filter out potential hits (Java regular expression syntax is used by Autopsy - http://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html). Therefore, the following expressions should be incorporated into a new Keyword List, as they provide the format currently in force for the respective data:

- For Bitcoin wallet addresses: ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$
- For Bitcoin private key strings: ^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$

3.
  1. Bitcoin Wallet Addresses

Bitcoin wallets are identified by hash strings with a length of 26 to 35 characters, and which are used to uniquely identify public wallets where Bitcoin can be transferred to by anyone, and spent only by the holder of the respective private key that was used to generate the address using public key cryptography. These hashes can be validated by performing a checksum on the last four bytes, which must correspond to the first four bytes of a double SHA-256 one way hash function digest of the previous 21 bytes.

The Bitcoin module performs, for all valid addresses found, a call to the Blockchain API to retrieve relevant data pertaining to that address, such as the time the wallet was first seen in a transaction, its current balance and the total amount received in that wallet since it was first seen.

3.
  2. Private keys

The private key candidate strings are validated by using the Elliptic Curve Digital Signature Algorithm to try to translate them to public wallet addresses, and running the same wallet address verification used above. The principle is that if a valid wallet address is generated (which was achieved through the pure Python ECDSA cryptographic signature library), then the Blockchain API will return a result, even if that wallet never participated in a transaction.

Even though private keys obtained with this approach may lead to unused wallets, they are still relevant information, as they may provide proof of intent to engage in illegal activities within the broader scope of an investigation.

