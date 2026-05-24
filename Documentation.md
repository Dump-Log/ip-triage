# Problem Definition
### 1. Specific Problem this addresses
   - When triaging multiple alerts from various sources, IPS, SIEM, EDR, it can be
troublesome to determine if some alerts are false positives or likely malicious. This tool provides aggregrate
informaiton from multiple sources to help make a determination quickly.
   - Having clear information to add to your notes can also be a challange when working directly with web sites.

### 2. Why is this problem important
- When triaging multiple alerts having to spend time analysing IP's can take extra time which delays containment actions if they are nescessary.
- Since it aggregates the important information, it is easier to copy the results into working notes without having bulky screen shots.

### 3. Existing tools or approachces
-  There are multiple free services, but these often may only show partial information, depending on how users report IP's.
- There are a few existing projects online that aim to also aggregate multiple services into 1 script.
- Of course there are mutliple paid services, some of the free services also have a paid tier with higher API usage, or additional information.
### 4. What Gap does this tool Fill
-  I needed a tool that was free, and only returned the information I specifically wanted. The few other projects I could find
which aimed to accomplish the same thing, usually returned to much information.
- I also needed a link to each tool generated and provided to save time in case I did need to explore the additional information further.
- I also needed a tool that could handle Fanged or Defanged IP's, depending on the alert source, I may be handling either.
# System Design
#### 1. High Level Architecture
- An IP is provided via command line
- A thread is created for each service to handle the API reqeust
- Once all requests are received, it prints the results

#### 2. Technologly choices and justification
- Python was picked because it is easy and fast to implement
- Free services are picked because they offered a free API and have trusted results
- Providing the IP address via command line was a compromise because using API's of the products I receive alerts from would have been difficult 
to reproduce and also make it less general purpose.
# Evaluation
#### 1. How I tested
- I used IP addresses from actual alerts at work where the IP was identified as likely malicious.
#### 2. Results
- The results from the script matched what the webservice also provided
#### 3. Known Issues
- If the IP address is not known by the service then no meaningful results are returned.