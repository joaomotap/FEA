# FEA - Forensics Enhanced Analysis

by João Mota (2017)

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

Estudante n.º 2161328


Work developed under the guidance and coordination of Prof. Patrício Domingues and Prof. Miguel Frade


### Abstract

This project explores the Autopsy digital forensics analysis platform and the underlying Sleuthkit framework, their modular architecture, and their extensibility through scripting. Throughout the research, three distinct modules are developed with different purposes, but with similar approaches. Primarily, the new modules aim to improve existing features, such as the email and credit card number search capabilities of the platform which are built-in to one of the default ingestion modules, and secondly, to incorporate new features which can take further advantage from the insights gained, namely by adding Bitcoin2 wallet address and private key search and validation processes.


### List of Acronyms

| API | Application Programming Interface |
| --- | --- |
| CFReDS | Computer Forensic Reference Data Sets |
| CSV | Comma separated values |
| DNS | Domain Name Server |
| FEA | Forensics Enhanced Analysis |
| GUI | Graphical User Interface |
| JDK | Java Development Kit |
| JVM | Java Virtual Machine |
| TLD | Top Level Domain |
| TSK | The Sleuth Kit |


### 1. Introduction

The increasingly widespread usage of computer systems, in their many shapes and sizes, has made forensic analysis an increasingly relevant field of work, since any investigation case now includes myriads of files obtained from these devices to sift through, in search of potential evidence, or valuable data that can lead to evidence. These relevant pieces of information - often designated &quot;artifacts&quot; in the scope of an investigation - can include browser history items, operating system registry entries, phone numbers, emails, email addresses, credit card numbers and bitcoin wallet addresses among many others. All of them are more or less relevant depending on the subject of the investigation, but email addresses are beyond a doubt artifacts of particular interest in the vast majority of cases, since they may establish relationships between interesting parties, or bring to light email or social media accounts unbeknownst up to the moment of being discovered[CITATION Row16 \l 2070].

The starting point for this project has therefore focused on the development of tools to improve the quality of data produced by software that gathers artifacts from data sources retrieved in the course of a forensics analysis procedure, specifically by applying several different techniques to detect email addresses harnessed by data extraction tools. The project was initially dubbed &quot;Filter Email Addresses (FEA)&quot;, but during the course of development, it quickly became apparent that additional features of relevance to forensics analysis could be developed using the same approach, and finally the project ended up being named &quot;Forensics Enhanced Analysis&quot;, and comprising of three separate tools: i) for email filtering and validation, ii) for credit card number validation and iii) for Bitcoin wallet addresses and private key search and validation.

To reach the goals of the email filtering module, several different techniques were put to use, such as performing alphanumeric checks on email addresses, crosschecking the existence of the top-level domain (TLD) through regularly updated online sources, performing DNS verifications on the email domain, and looking up the _Internet Archive_ (archive.org) for addresses that are syntactically valid, but that have failed the DNS check, in order to assess whether the domain might&#39;ve existed in the past.

The credit card module is probably the simplest of the three, since it merely requires that numbers matching the relevant regular expression to be verified with a Luhn checksum[CITATION Wik17 \l 2070], allowing for quick validation of false positives.

Finally, the Bitcoin module draws inspiration from the _Internet Archive_ validation method used in the email filtering module, and verifies the existence and available transaction data present in the _Blockchain_ (blockchain.info), to extract interesting information about this form of digital currency, which is typically associated to transactions where the parties have an interest in maintaining anonymity.

It is expected that the tools developed during the course of this project will provide convenient assistance to forensics experts using Autopsy, as they all target data that is typically of high relevance within this field of work, especially when dealing with suspected fraud, financial crimes, tax evasion, transaction of illegal goods or services, and so on. Hopefully the tools will relieve investigators of the tedious task of sifting through high volumes of irrelevant data, and improve overall efficiency of the whole investigation process.


### 2.Background

1.
  1. 1The Sleuth Kit and Autopsy

Out of the many products available in the domain of Digital Forensics, The Sleuth Kit (https://sleuthkit.org) (TSK) is one of the best-known sets of open-source tools that provide industry standard techniques for undertaking many common forensics analysis tasks, with the Autopsy application (http://www.sleuthkit.org/autopsy/) providing a unified Graphical User Interface (GUI) for it.

The Sleuth Kit is capable of processing several different types of filesystems as well as forensic image formats, such as E01 and AFF[CITATION Sim10 \l 2070], from which it is also capable of accessing unallocated space. Besides direct processing of binary data, The Sleuth Kit provides specific services, such as interpreting EXIF metadata, identifying existing operating systems in forensic images, extracting web activity from common browsers to help identify user activity, file type sorting, hash set filtering using the NSRL (National Software Reference Library - https://www.nist.gov), displaying system events in a graphical interface to help identify activity, among others. The Autopsy application then aggregates all of these features under a unified GUI, being extensible through its plugin architecture or via leveraging other external tools – for example, recovering content identified as erased is performed through the external tool _PhotoRec_, and extracting Windows registry data is achieved through the external tool _RegRipper_[CITATION Pan13 \l 2070].

As a free-to-use open source product, Autopsy has had strong support from users and contributors, and has been kept up to date with the latest techniques and best practices of the industry, greatly due to community-driven development, made easy by its modular plugin architecture based in Java and Python, that allows for rapid extensibility.

One of the standard features of the Sleuth Kit exposed by Autopsy is the Keyword Search module, which uses Lucene SOLR (https://lucene.apache.org/index.html) for indexed keyword searching and includes specific features for identifying email addresses and credit card numbers retrieved from data sources (forensic images) - but has a sufficiently generic architecture to allow it to be used in several different types of searches. However, that same generic architecture and approach to data ingestion means that it often generates false positives, since it only broadly checks the data being processed, preferring to consider any strings resembling an electronic email address to be accepted as such. This can obviously slow down the forensic analysis process, and in more extreme situations can even end up preventing the identification of email addresses relevant to the respective investigation.

The initial purpose of this project was to specifically improve the email address search functionality included by default in Autopsy via Keyword Search, which was to be achieved by creating additional layers of validation to the standard modules, in order to filter and reduce the currently exaggerated number of false positives it yields. However, throughout the development of this feature, it became apparent that other relevant contributions could be made by leveraging the same knowledge garnered in the process, and two additional modules were built: one for finding and validating credit card account numbers, and another for dealing with potential Bitcoin wallet addresses.

In order to achieve these goals, it was decided to build on Autopsy&#39;s keyword search features instead of refactoring them, in order to ensure that the developed work is not rendered unusable, and rather takes advantage of further evolutions incorporated in the future by the community.

1.
  1. 2Autopsy Modules

Given Autopsy&#39;s open architecture, there are strong community efforts to develop modules with varied purposes, that greatly enrich and extend the default module suite provided by the Sleuth Kit. These are split into three types, representing the cornerstones of the software&#39;s analysis process: ingestion, visualization and reporting.

Most of the modules available focus on the ingest phase, which makes sense as it is the most time-consuming and resource-intensive stage, and therefore can bring the most added value through optimization. The concept is to extract only the data that is relevant to the current investigation, and so many different modules are available, trying to cater for many common needs within the field. One of the most flexible ingest modules is included by default in the Sleuth Kit, and is called &quot;Keyword Search&quot;. This module includes a few default keyword lists to facilitate searching the selected data sources for phone numbers, IP addresses, URLs, Credit Card Numbers, and Email addresses. Nevertheless, these searches are basically filters for regular expressions, and incorporate no further validation of the artifacts gathered from the data sources – and even though it&#39;s possible to customize and add keyword lists by building more regular expressions or word lists, the possibilities are rather limited in terms of in-depth validation.

Data visualization modules, referred to as Data Content Viewer Modules, are also quite popular, and provide convenient ways to analyse artifacts gathered from data sources directly. These range from simple text viewers to video triage modules that facilitate viewing large video files by analysing their contents. Again, these are of no help for performing deep validation of email addresses and similar data, as they target individual files and not bulk processing of multiple artifacts.

Lastly, the report modules are seemingly a distant relative of the rest, since there are few contributions from the community, and as far as it was possible to determine, only the standard Sleuth Kit ones are available. Granted that those can satisfy the most common needs of reporting, but the fact is that their capacity to drill down on ingested data is clearly being underused, even though the Sleuth Kit&#39;s documentation tries to raise awareness to the fact that these are not meant just for producing information briefs, but can also provide a convenient vehicle for new tools to assist in the investigation process.

Autopsy&#39;s core modules can be easily extended through Jython scripts that get compiled on-demand at the launch of their respective stage (ingest, visualisation or reporting). Jython conveniently facilitates usage of Python syntax while running in the same Java Virtual Machine (JVM) as Autopsy [CITATION Jos11 \l 2070][CITATION Jos10 \l 2070], and therefore allowing access to its Application Programming Interface&#39;s (API) class hierarchy and object collection [CITATION AutopsyDevGuide \l 2070], and which in turn extends all the functionality of TSK [CITATION Bri13 \l 2070]. Simultaneously, all standard Python libraries are available to use, meaning the full power of Python&#39;s string manipulation operators and libraries can be taken advantage of, which is particularly relevant in the scope of this project.



1.
  1. 3Related work

The task of validating an electronic email address is an apparently simple one. It should be a matter of sending an email message to the address under investigation, and wait for the outcome, which would have only three scenarios where the address in use could safely be considered as not valid:

- --If the domain does not exist.
- --There is no server registered as an email exchange via an MX record of the DNS.
- --The message is returned.

However, this simplistic approach is not efficient for multiple reasons:

- --On the vast majority of email servers, the notification of invalid addresses is disabled, and upon reception of a message addresses to a non-existent user, will simulate a valid delivery. Even though this behaviour does not conform with RFC5321 [CITATION Kle08 \l 2070], which stipulates that such requests should produce error 550 with the string &quot;no such user&quot; (or similar), the fact is that issuing such a reply would allow malicious spam email applications to exploit the feature, in order to discover valid emails by randomly generating target addresses (and thus adding to the already disproportionate volume of unsolicited email being sent regularly).
- --Many email addresses currently not valid, might have been operational at the time of the facts under investigation.
- --Most importantly, within the specific context of forensic analysis, sending out test emails may cause unwanted events that can severely hinder on-going investigations, for example by alerting persons of interest or triggering the self-deletion of malicious software that could have been used as important evidence.

In the paper &quot;Making sense of Email Addresses on Drives&quot; [CITATION Row16 \l 2070] the authors use a Naïve Bayes classifier to detect false positives in a list of possible email addresses recovered from a vast number of hard drives. Test results showed 73% of the candidates were eliminated, marking them as false positives. However, the main scope of that study was to determine relations between social network accounts based on those email addresses, therefore reducing its value in the broader scope of forensic analysis.

In terms of other related work, it could be considered relevant to look into the state of the art of spam detection algorithms, given that it&#39;s a very mature and fast moving field of study, but the fact is that the field is rapidly adopting supervised learning algorithms which rely heavily on labelled data to produce optimal results, and are therefore over-fit to analysing email content, and not the addresses themselves. In conclusion, they bring no additional value to the works approached previously.

1.
### 3.FEA Development approach

After careful consideration of the goals of this project and the framework provided by Autopsy, it was decided that report modules coupled with custom keyword lists in the Keyword Search ingest module would incorporate the most adequate approach, with multiple advantages:

- Standard ingest modules are optimized in the way they tackle the task of doing the actual ingestion, and relying on them will ensure that this work will in the future take advantage of any updates that may be introduced by the community to that basic functionality.
- Existing cases with processed data will not have re-run the time-consuming ingestion process.
- The separation of scope means that the ingest stage does not have to be further burdened with resource-intensive tasks, allowing the investigator to cherry-pick the most relevant artifacts and types of analysis to be submitted to the report modules developed for the abovementioned specific purposes.
- Automatic creation of multiple reports in file formats that facilitate further manual processing (such as Microsoft Excel workbooks).

Therefore, three separate Jython scripts were developed, each with a configuration panel built in Java Swing, for analysis of email addresses, credit card account numbers and bitcoin keys &amp; addresses, all of them described in detail below.

Playing a key role in any of these modules is the Blackboard class of objects provided by TSK&#39;s API, and which consists of a collection of &quot;artifacts&quot;, each consisting of name-value pairs called &quot;attributes&quot;, which are used to share information across modules.

Each module can post or get data from the Blackboard, with the purpose of collaboratively solving a problem, and the standard Autopsy modules are no exception. In order to access the Blackboard from a Jython script, both the _SleuthkitCase_ object and the _Content_ object can be used. In the former case, a comprehensive list of the Blackboard&#39;s artifacts can be retrieved through one of the many _getBlackboardArtifacts_ methods. In our case, the artifacts generated by the Keyword Search standard ingest module are used for further processing.

All of the modules were developed and tested with Autopsy for Windows version 4.3.0, dated July 19, 2016, version 4.4.0, dated May 30, 2017 and version 4.4.1, dated Aug 9, 2017.

1.
  1. 1Email Report Module

The goal of this report module is to perform additional validation of the strings captured as emails by the Keyword Search ingestion module, which puts results into the Blackboard as artifacts containing the attribute TSK\_SET\_NAME with the value &quot;Email Addresses&quot;.

TSK&#39;s API allows us to retrieve every artifact generated during ingestion, and then iterate through each of its attributes to retrieve the actual email address strings, which are stored as type &quot;TSK\_KEYWORD&quot;.

After identifying each relevant string, the following validations are (optionally) performed:

1.
  1.
    1. 1.1Top Level Domain (TLD) Validation

This validation pertains to the last part of the domain name of an email address (e.g. COM in the case of _google.com_).

The official TLD database is maintained by IANA, the Internet Assigned Numbers Authority, through its &quot;Root Zone Database&quot;, and it includes the standard EDU, COM, NET, ORG, GOV, MIL and INT identifiers, country TLDs that incorporate a two-character code corresponding to the ISO-3166[CITATION Pos94 \l 2070] standard.

The implemented software resorts to scraping the website to retrieve valid TLDs, since there is no public API or any such service available for doing so that could be found. This relies on the list made public on https://data.iana.org/TLD/tlds-alpha-by-domain.txt, and which is updated on a daily basis. This list is retrieved just before the start of the artifacts processing algorithm, and each time the module is ran, in order to ensure that the latest version is being used.

After the list is made available, each string is iterated to verify if the substring after the last dot character (&quot;.&quot;) matches any of its entries, and classifying artifacts accordingly, by marking as false positives any addresses with invalid TLDs. Any addresses that fail the TLD verification will not undergo further verifications, since they can already be safely classified as false positives, beyond any reasonable doubt.

1.
  1.
    1. 1.2Alphanumeric syntax check

One of the simplest email address validation procedures that the Keyword Search ingest module overlooks is verifying whether the strings contain only alphanumeric characters, as per the rules for email address syntax defined in RFC5322 [CITATION PRe08 \l 2070], duly adjusted to the most common current implementation. As an example of an exception, RFC5322 allows the inclusion of free text comments in the part of the email address preceding the &#39;@&#39; symbol, if enclosed in parenthesis, but the vast majority of email services today do not provide any support for this rule, and allow only alphanumeric characters, dots (.), underscores (\_) and hyphens (-). For the purposes of the project, it was decided that the module would follow this typical validation.

The report module implements the validation by crosschecking every domain against the appropriate regular expression:

 &quot;^[\_a-z0-9-]+(\.[\_a-z0-9-]+)\*@[a-z0-9-]+(\.[a-z0-9-]+)\*(\.[a-z]{2,4})$&quot;.

1.
  1.
    1. 1.3Domain name validation

If the user choses to do so in the module configuration settings - which is optional due to the resource-intensive nature of this task - a Domain Name Server (DNS) lookup is performed for the domain portion of each email address (following the &#39;@&#39;), after discarding duplicate entries.

Since the lookup request is a blocking process, an asynchronous multi-threaded approach was applied, and the user can further decide on the number of simultaneous threads to be made available to the process, according to preference or available resources, via the Java Swing configuration panel presented before running the module. Therefore, a decision can be made on whether to privilege fast execution with a larger volume of simultaneous DNS requests, or instead, to have slower execution but with a reduced impact on the service. In any case, it should be noted that simultaneous requests to the DNS service are frequent in many applications (e.g., web browsers [CITATION Duc99 \l 2070]), without posing a problem from the perspective of service availability, which in the case of DNS, is known to be quite scalable [CITATION Jae02 \l 2070].

Each thread will launch a domain lookup task that relies on the java.net standard Java Development Kit (JDK) library to perform the lookup request, and returning results to the thread queue structure3.

A potential future improvement would be to build a local cache of domain lookup verifications as they are run across Autopsy Cases in order to shorten processing times, but it is not a trivial task as it requires persisting information in such a way that would not be limited by the frameworks sandboxed architecture, and outside the scope of the current project.

1.
  1.
    1. 1.4Internet Archive validation

The fact that a DNS lookup currently returns an inexistent domain does not necessarily mean that it was not once in existence. Domain name registrations are valid for a limited amount of time, and in case they are not renewed by their respective owner, or acquired by someone else, they cease to exist.

One way around this obstacle would be to search for the domain name being investigated in DNS registration history. However, there are two key limitations to this option: i) existing services do not support all of the currently valid TLDs, and ii) such services are not freely available, and using them would restrict FEA&#39;s usage and adoption.

The Wayback Machine or Internet Archive4 on the other hand, is a non-profit library with the self-proclaimed mission of providing Universal Access to All Knowledge, that makes available 20+ years of web history[CITATION Abo17 \l 2070]. Considering it hosts data referring to about 279 billion webpages, it was considered to be of interest to give users the option to further verify email domains against this vast database, and thus assess if these were ever registered in the past – and provide some insight on the content they might have been serving. Even though the Wayback Machine is certainly not a comprehensive list of every website ever made, it undoubtedly contains sufficient data to make it an interesting resource within the scope of this project.

Conveniently, the Wayback Machine provides an API to facilitate queries to its records, returning a JSON object containing details on every snapshot available at the archive for any given domain address, including a timestamp referring to its date of inclusion[CITATION Way13 \l 2070][CITATION How06 \l 2070].

The module thus queries the Wayback Machine API for every domain address that failed the DNS lookup validation, and stores a link to the last version ever seen online according to the archive, if available, adding it to the final report. The queries are performed in sequence, with no option for multithreaded processing, in order to avoid flooding the service with requests.

Within the scope of a typical forensic analysis, the assessment of past existence of a domain is of particular interest, since it is quite frequent that malicious activity is based on servers running on domains registered specifically for that purpose, to be discarded shortly after. Nevertheless, there is no guarantee that Internet Archive records are exhaustive, for a number of reasons: i) the service might not have had time to index domains that existed for brief periods of time, ii) the service&#39;s web crawler prioritizes websites according to its own ranking system, based on popularity and number of times the target showed up on searches, and thus might not index websites that have been online for longer periods, and iii) the owners of the website(s) might have explicitly requested to not have the website indexed by crawlers, either directly to the Wayback Machine, or via installation of a robots.txt flag, which is a universal technical standard (called the SRE – standard for robot exclusion) for indicating a preference to not have a website crawled, and which the Internet Archive abides by.

Finally, it should be further noted that even if a given domain name is referenced by the Internet Archive, that does not prove that the email address actually existed, since there is no guarantee that the domain was used for email services.

1.
  1.
    1. 1.5Reported data

Depending on user preference, one or two files can be added to Autopsy&#39;s collection of reports containing the output of the module, and which includes, for each email address found by the Keyword Search ingest module, the following status information:

- Alphanumeric check
- TLD check
- DNS Lookup verification
- Wayback Machine / Internet Archive lookup
- Distinct valid domain names and number of occurrences (hits)

If the user has so decided in the report configuration dialog box, an Excel Workbook is generated with two distinct sub sheets containing this information, and which can be used for further filtering and processing.  This process relies on the xlwt pure Python open source package library, which is in turn based on the pyExcelerator package [CITATION Wor \l 2070]. Regardless of opting to generate an Excel report, a CSV file with the module&#39;s results is always added to Autopsy&#39;s reports list.

1.
  1. 2Credit Card Accounts Report Module

A separate module was developed exclusively for addressing investigation of credit card numbers present in the forensic data source. Like it does for email addresses, Autopsy also provides a list of potential credit card numbers. The approach is similar to the previous module, and the Keyword Search module is used for obtaining the credit card numbers, which in terms of ingestion differ only in the attribute type added to the result set of artifacts (TSK\_ACCOUNT), and the attribute type of the string value with the actual numbers (TSK\_CARD\_NUMBER).

As for the validation, a Luhn algorithm [CITATION Wik17 \l 2070] is ran to perform a checksum on each number. Also known as the &quot;modulus 10&quot; or &quot;mod 10&quot; algorithm, it provides a simple validation mechanism that works by appending a check digit to the end of a partial account number to generate the full account number, that must pass a verification test:

- --From the rightmost digit, which is the check digit, and moving left, double the value of every second digit. If the result of this doubling operation is greater than 9 (e.g., 8 × 2 = 16), then add the digits of the product (e.g., 16: 1 + 6 = 7, 18: 1 + 8 = 9) or alternatively subtract 9 from the product (e.g., 16: 16 - 9 = 7, 18: 18 - 9 = 9).
- --Take the sum of all the digits.
- --If the total ends in zero, then the number is valid according to the Luhn formula.

This process is widely used for validation of credit card numbers, and specified in ISO/IEC 7812-1, with the main purpose of protecting against accidental errors, but which serves the current purpose of rapidly identifying false positives [CITATION Wik17 \l 2070].

It is known that the algorithm if flawed with a transposition error, since transposing digits 09 for 90 cannot be detected, and therefore it cannot be relied upon for an absolute validation of the account numbers [CITATION Wan15 \l 2070]. Nevertheless, for the purposes of improving validation of false positives, it is an enhancement of the core features of Autopsy, and will contribute for enhancing data quality and reduce time needed for analysis.

1.
  1. 3Bitcoin Addresses &amp; Keys Report Module

One other increasingly interesting type of artifact to be recovered from digital forensics analysis case files are those connected with cryptocurrencies, considering these are often associated with potentially malicious actions, or at least worthy of further investigation. Recent high profile and fast spreading ransomware making use of the anonymity provided by these potential payment gateways are a perfect example of the high interest in locating traces of Bitcoin addresses or even private keys that may be stored in the available data sources [CITATION FBI12 \l 2070].


The distributed nature of transaction validation is the basis for the anonymous nature of Bitcoin. Since it does not require a central authority to validate transaction signatures, there is no mechanism that allows involuntary identification of the owner of the funds, as no such record is maintained [CITATION Nak08 \l 2070]. However, this poses a risk to the owner of the funds, since it will only be possible to access them by knowing the bitcoin wallet address and corresponding private key. Although best practices dictate keeping this information in encrypted storage, that is not always the case, and thus an opportunity arises for collecting this information during a forensics investigation.

Currently, Autopsy does not support any built-in tools to facilitate the discovery of such artifacts, however the Keyword Search module can again be put to use, by creating custom lists with regular expressions to filter out potential hits (Java regular expression syntax is used by Autopsy - http://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html). Therefore, the following expressions should be incorporated into a new Keyword List, as they provide the format currently in force for the respective data:

- For Bitcoin wallet addresses: &quot;^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$&quot;
- For Bitcoin private key strings: &quot;^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$&quot;

This can be achieved via the &quot;Options&quot; menu in Autopsy, under the &quot;Keyword Search&quot; tab.


1.
  1.
    1. 3.1Bitcoin Wallet Addresses

Bitcoin wallets are identified by hash strings with a length of 26 to 35 characters, and which are used to uniquely identify public wallets where Bitcoin can be transferred to by anyone, and spent only by the holder of the respective private key that was used to generate the address using public key cryptography [CITATION Bit171 \l 2070]. These hashes can be validated by performing a checksum on the last four bytes, which must correspond to the first four bytes of a double SHA-256 one way hash function digest of the previous 21 bytes [CITATION Bit17 \l 2070][CITATION Bit16 \l 2070].

All bitcoin transactions are securely recorded in the so called Blockchain, which is literally a chain of blocks. Each block of the chain holds up to 1 MB of bitcoin transactions. All this data is publicly available and can be queried through the Blockchain API. Figure 7 shows transaction data pertaining to the bitcoin wallet with address 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn. This wallet was one of the three used by the infamous ransomware &quot;WannaCry&quot; that crippled many computer systems in May 2017.

The Bitcoin module performs, for all valid addresses found, a call to the Blockchain API to retrieve relevant data pertaining to that address, such as the time the wallet was first seen in a transaction, its current balance and the total amount received in that wallet since it was first seen [CITATION Blo \l 2070].

1.
  1.
    1. 3.2Private keys

The private key candidate strings are validated by using the Elliptic Curve Digital Signature Algorithm to try to translate them to public wallet addresses, and running the same wallet address verification used above [CITATION Ell15 \l 2070]. The principle is that if a valid wallet address is generated (which was achieved through the pure Python ECDSA cryptographic signature library), then the Blockchain API will return a result, even if that wallet never participated in a transaction.

Even though private keys obtained with this approach may lead to unused wallets, they are still relevant information, as they may provide proof of intent to engage in illegal activities within the broader scope of an investigation.

1.
### 4.Test results

Three distinct forensic images were used for undertaking the tests described below, taken from experimental cases containing relevant data.

1.
  1. 1Test scenario

FEA was evaluated in a test scenario with forensic images acquired from three distinct operating systems: Windows 7, Windows 8.1 and Mac OS X. Additionally, they correspond to different usage profiles: Windows 8.1 and Mac OS X images come from systems with a low volume of usage, ie., they are basically just the installation of the operating system with few applications installed. On the other hand, the Windows 7 image corresponds to a system intensely used in an academic environment, with multiple personal files present and a significant number of installed applications. The following table summarizes the characteristics of the images:

Table 1. Test scenario profiles

| ID | Win7 | Win8.1 | Mac OS X |
| --- | --- | --- | --- |
| Operating System | Windows 7 | Windows 8.1 | Mac OS X 10.11.4 |
| Size (GB) | 232.89 | 40 | 226 |
| Email addresses (Autopsy) | 18 203 | 2 085 | 21 557 |



The last row shows the total number of potential email addresses identified by Autopsy, for each data source.

The tests were run in a laptop computer equipped with an Intel Core i5-2410M@2.30GHz, with 4GB of RAM and an SSD hard drive. Version 4.3 of Autopsy was used, running on Windows 10 64-bit operating system.

1.
  1. 2Main findings

The FEA email validation module was run for all three images, with the following results:

1.
  1.
    1. 2.1Alphanumeric syntax validation test results

Table 2 shows the results obtained from applying the alphanumeric syntax validation features of FEA on all three images under analysis. This validation was found to exclude only about 2% of the unique email addresses found by Autopsy. We can therefore assume that in this respect, the ingest module is efficient in producing the initial list of email addresses, with a low number of false positives being included.

Table 2. Alphanumeric syntax validation results

| Syntax validation | Win7 (%) | Win8.1 (%) | Mac OS X (%) |
| --- | --- | --- | --- |
| Valid | 7 664 (98.79%) | 938 (97.91%) | 5 762 (97.79%) |
| Not valid | 94 (1.21%) | 20 (2.09%) | 130 (2.21%) |
| Unique | 7 758 (100%) | 958 (100%) | 5 892 (100%) |



1.
  1.
    1. 2.2Top level domain validation test results

Table 3 shows the results for the validation of TLDs. The results here are quite significant, with a 94.60% ratio of false positives being detected for Mac OS X, 72.44% for Win8.1 and 33.18% for Win7. It&#39;s reasonable to expect that the considerable difference across the three systems is due to the different usage profile on each of them. As such, systems Win8.1 and Mac OS X, having less usage, few applications installed, and few personal files, show a relatively higher percentage of false positives as they are much less likely to contain valid email addresses in significant numbers. Conversely, with Win7 having more installed applications and more personal files, will have a correspondingly higher number of valid email addresses. In the particular case of Mac OS X, a large number of candidate addresses ending in .png (e.g., battery\_discharging\_45@2x.png) was found, which in practice correspond to PNG files included in the operating system itself. This has significant influence in the high percentage of false positives identified by the TLD validation.

Table 3. Top level domain validation results

| TLD validation | Win7 (%) | Win8.1 (%) | Mac OS X (%) |
| --- | --- | --- | --- |
| Valid | 5 184 (66.82%) | 264 (27.56%) | 318 (5.40%) |
| Not valid | 2 574 (33.18%) | 694 (72.44%) | 5 574 (94.60%) |



1.
  1.
    1. 2.3DNS Lookup validation test results

Table 4 shows the results for the DNS lookup validation. It shows that domain name validation identifies a large number of unregistered domain names (at the time of running the validation), specially in the images from the Windows operating systems. Namely, 74.43% of the email addresses listed by Autopsy&#39;s ingest module ran on the Win8.1 image are marked invalid, 44.79% for the Win7 image and 26.98% for the Mac OS X image.

Table 4. DNS lookup validation results

| DNS validation | Win7 (%) | Win8.1 (%) | Mac OS X (%) |
| --- | --- | --- | --- |
| Valid | 2 833 (55.21%) | 245 (25.57%) | 230 (73.02%) |
| Not valid | 2 298 (44.79%) | 713 (74.43%) | 85 (26.98%) |



1.
  1.
    1. 2.4Internet Archive validation test results

The Internet Archive validation is only run for domains that have valid syntax but with no valid domain names registrations found. The results are shown on Table 5.

It was found that for system Win7, 540 domains (22.97%) that had been marked as not valid by the DNS lookup validation were found to have existed sometime in the past. The results for the remaining two systems are comparatively lower in volume and higher in relative occurrence, certainly due the aforementioned usage profiles, but in any case 12 such domains were found in the Win8.1 system (63.16%) and 38 in the Mac OS X system (43.18%).

Table 5. Internet Archive validation results

| Internet Archive validation | Win7 (%) | Win8.1 (%) | Mac OS X (%) |
| --- | --- | --- | --- |
| Recorded | 540 (22.97%) | 12 (63.16%) | 38 (43.18%) |
| Not recorded | 1 811 (77.03%) | 7 (36.84%) | 50 (56.82%) |
| Total | 2 351 (100%) | 19 (100%) | 88 (100%) |

1.
  1.
    1. 2.5Test result summary

As seen from the results, the FEA&#39;s multiple validations provide important insights depending on the usage profile of the images under investigation. For low usage profiles, syntax and DNS verifications can quickly rule out most of the false positives. When a lot of candidates are present though, the DNS lookup validation with the Internet Archive validations allow investigators to drill-down on valid addresses efficiently. For the high usage profile case of Win7, a total of 1811 false positives were detected using this approach, representing about 23% of the total number of unique addresses gathered by Autopsy. But asides from that, 540 addresses corresponding to domain names that are no longer active can now also be identified, with cached versions of any related websites potentially available for further investigation in the Internet Archive.

1.
### 5.Conclusions and Future Development

This project has made it clear that there is a lot of value to be added to the digital forensics analysis process proposed by Autopsy and TSK by leveraging intelligence contained in the results it produces through the creation of more or less sophisticated report modules.

Up until now, this invaluable resource has been underutilized by the community, perhaps on one hand due to its &quot;post-factum&quot; nature that places it as a mere reporting tool, and on the other hand because the primary focus of the typical Autopsy user is to collect as much potentially relevant data as possible for further processing in external tools later.

Nevertheless, the fact that additional processing can be achieved in this so-called reporting stage, means that the modules can be a powerful triage tool, as evidenced by the results of the project, harnessed by employing very simple techniques to filter the results of the ingest modules.

FEA was able to remove many of the false positives identified by Autopsy, notably reducing the number of email addresses that need to be considered by the digital forensics investigator, allowing him/her to focus on addresses with a high probability of being real and therefore contributing to the investigation.

Through Luhn&#39;s validation, FEA also filters out some false positive strings that could be flagged by Autopsy as valid credit cards. Again, this aims to reduce the workload of the forensics investigator, as some false positives are properly identified.

The Bitcoin reporting capabilities of FEA is an interesting add-on to Autopsy. It detects public and private bitcoin keys, when those exist in a string format. It provides the Autopsy tool with a new capability. Due to the growing relevance of the electronic money Bitcoin, namely in money transactions, the module can alert the forensic investigator for evidences related to Bitcoin usage.

1.
  1. 1Future Development

The current work incorporates an initial approach to the subject of report modules in the Autopsy platform, and it is clear that there is some potential for future developments.

Work is underway to allow for the creation of exception lists and masks, in order to allow the user to relieve known addresses from the analysis process. Domain names like &quot;_contoso_.\*&quot;, a fake company and domain name used in Microsoft&#39;s documentation examples, as well as &quot;_example_.\*&quot;, are good of examples of such situations.

Additional presentation improvement opportunities are also very clear, such as statistical data that can be easily incorporated into all three report modules, to provide quick insights on percentages of false positives, distribution histograms, interesting files arising from the report analysis, generation of interesting items lists directly in the Blackboard, etc. Creating filtered lists in Autopsy&#39;s Blackboard for viewing in the main interface are also desirable, as these could allow a quick drill down to the most relevant artifacts (e.g. lists of addresses with currently valid domains, lists of URLs linking to Internet Archive records for currently invalid domains, etc).

Specifically regarding the Bitcoin search module, additional features could also be relevant, such as support for different types of cryptocurrencies, or validation of wallet addresses and public/private keys in different formats.

Lastly, some consideration should be given to the application of machine learning algorithms to further validate email addresses, and classify them according to their probability of being false positives, or even potential interest for further investigation. This would allow generic addresses to be quickly ruled out, and further improve the results, with the potential for generating increasingly more effective predictive models over time.

The work now developed certainly simplifies the incorporation of these and eventually other features, since it provides the basis for accessing relevant data extracted from the ingest modules before persisting it to the final report files, which will facilitate future development.













#
### Bibliography

| [1] | N. C. Rowe, R. Schwamm, M. R. Michael e R. Gera, Making Sense of Email Addresses on Drives, Monterey, California: U.S. Naval Postgraduate School, 2016. |
| --- | --- |
| [2] | Wikipedia, &quot;Luhn algorithm,&quot; 12 03 2017. [Online]. Available: https://en.wikipedia.org/wiki/Luhn\_algorithm. |
| [3] | S. L. Garfinkel, &quot;Open Source Digital Forensics Conference (OSDFCon),&quot; Chantilly, 2010. |
| [4] | E. P. Panchal, &quot;Extraction of Persistence and Volatile Forensics Evidences from Computer System,&quot; _International Journal of Computer Trends and Technology (IJCTT),_ vol. 4, nº 5, pp. 964-968, 5 May 2013. |
| [5] | J. Juneau, &quot;Jython 2.5.2 Documentation,&quot; 03 03 2011. [Online]. Available: http://www.jython.org/docs/index.html. |
| [6] | J. B. V. N. L. S. F. W. Josh Juneau, The Definitive Guide to Jython, Creative Commons 3.0, 2010. |
| [7] | Basis Technology, &quot;Autopsy Forensic Browser Developer&#39;s Guide and API Reference,&quot; 2012-2016. [Online]. Available: http://www.sleuthkit.org/autopsy/docs/api-docs/4.3/. |
| [8] | B. Carrier, &quot;The Sleuth Kit (TSK) Framework User&#39;s Guide and API Reference,&quot; 2011-2013. [Online]. Available: https://www.sleuthkit.org/sleuthkit/docs/framework-docs/index.html. |
| [9] | J. Klensin, &quot;RFC 5321: Simple Mail Transfer Protocol,&quot; Network Working Group, October 2008. [Online]. Available: https://tools.ietf.org/html/rfc5321. [Acedido em 05 08 2017]. |
| [10] | J. Postel, &quot;Domain Name System Structure and Delegation,&quot; 30 March 1994. [Online]. Available: https://www.ietf.org/rfc/rfc1591.txt. [Acedido em 07 07 2017]. |
| [11] | P. Resnick, &quot;IETF Tools,&quot; 30 10 2008. [Online]. Available: https://tools.ietf.org/html/rfc5322. [Acedido em 07 09 2017]. |
| [12] | D. Duchamp, &quot;Prefetching hyperlinks,&quot; em _USENIX Symposium in Internet Technologies and Systems_, Boulder, Colorado, 1999. |
| [13] | E. S. H. B. M. I. a. R. M. Jaeyeon Jung, &quot;DNS Performance and the Effectiveness of Caching,&quot; _IEEE/ACM Transactions on Networking,_ vol. 10, nº 5, pp. 589-603, October 2002. |
| [14] | &quot;About the Internet Archive,&quot; The Internet Archive, [Online]. Available: https://archive.org/about/. [Acedido em 27 06 2017]. |
| [15] | &quot;Wayback Machine APIs,&quot; 24 9 2013. [Online]. Available: https://archive.org/help/wayback\_api.php. |
| [16] | B. A. Howell, &quot;Proving Web History: How to use the Internet Archive,&quot; _Journal of Internet Law,_ vol. 9, nº 8, pp. 3-9, February 2006. |
| [17] | &quot;Working with Excel Files in Python,&quot; [Online]. Available: http://www.python-excel.org/. |
| [18] | K. W. L. N. Wangeci Wachira, &quot;Transposition Error Detection in Luhn&#39;s Algorithm,&quot; _International Journal of Pure and Applied Sciences and Technology ,_ vol. 30, nº 1, pp. 24-28, 2015. |
| [19] | F. -. D. o. Intelligence, &quot;(U) Bitcoin Virtual Currency: Unique Features Present Distinct Challenges for Deterring Illicit Activity,&quot; FBI, Washington DC, 2012. |
| [20] | S. Nakamoto, &quot;Bitcoin: A Peer-to-Peer Electronic Cash System,&quot; 31 November 2008. [Online]. Available: http://www.bitcoin.org/bitcoin.pdf. [Acedido em 07 09 2017]. |
| [21] | &quot;Bitcoin Wikipedia Page,&quot; Wikipedia, [Online]. Available: https://en.wikipedia.org/wiki/Bitcoin. [Acedido em 28 06 2017]. |
| [22] | &quot;Bitcoin/address validation,&quot; 05 04 2017. [Online]. Available: https://rosettacode.org/wiki/Bitcoin/address\_validation#Python. |
| [23] | &quot;Bitcoin Address,&quot; bitcoinwiki, 06 09 2016. [Online]. Available: https://en.bitcoin.it/wiki/Address. [Acedido em 28 06 2017]. |
| [24] | &quot;Blockchain Query API,&quot; [Online]. Available: https://blockchain.info/q. |
| [25] | &quot;Elliptic Curve Digital Signature Algorithm,&quot; bitcoinwiki, 10 02 2015. [Online]. Available: https://en.bitcoin.it/wiki/Elliptic\_Curve\_Digital\_Signature\_Algorithm. [Acedido em 28 06 2017]. |
| [26] | B. Akar e M. Tekalp, &quot;Transport methods in 3DTV ...&quot;,&quot; _IEEE Trans._ _On Circuits and Systems On Video Technology,_ vol. 17, Novembro 2007. |
| [27] | J. Keffer, &quot;Autopsy Forensic Browser User Guide,&quot; 2013. |
| [28] | A. Pinto, &quot;Investigação digital com Autopsy,&quot; 2017. |
| [29] | &quot;The CFReDS Project,&quot; NIST, 15 09 2016. [Online]. Available: https://www.cfreds.nist.gov/. [Acedido em 28 06 2017]. |





1

#
 Bitcoin é uma criptomoeda e forma de pagamento digital descentralizado, muito popular entre ciber criminosos que pretendam preservar a anonimidade durante a realização de pagamentos em transações ilegais, e por isso relevante para o âmbito de perícias forenses

2

#
 Bitcoin is a worldwide cryptocurrency and digital payment, widely popular among cyber criminals intending to preserve anonymity when performing payments in illegal transactions, and therefore relevant to the scope of digital forensics

3

#
 This algorithm has been placed on a Jython library external the module&#39;s script (&quot;jm\_domain\_lookup.py&quot;) for the sake of better organization of the code, but it should be noted that Autopsy will only compile external libs when it first runs a module script, and any changes to such external files will be disregarded after that first run, so due care needs to be taken in order to avoid issues that will become hard to trace.

4

#
 https://archive.org