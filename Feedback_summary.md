## Feedback summary & Changes

handle invalid IP addresses
- added input validation for each IP given

Handle mutliple IP addresses
- updated to take 1 or more IP address seperated by a space 

Cisco Talos Results
- Removed, I received multiple comments about missing results and only returning the URL, Cisco Talos does not have an API, and the cisco api to 
get this threat intelligence is not free, so it was removed.
- it was replaced by GreyNoise which has a free API and good relevant results.

Output Analysis
- Generally I'm only using this tool when another tool has already triggered on the IP, and I need to gather more evidence to determine if it
was a false positive, or true positive. With that in mind, I'd prefer to keep the human in the loop and determine this myself.

.env file for api keys
- this was a good catch and not something I considered, I don't often work with API's in public repos so this was a good learning opportunity
- API keys moved to a .env file to clean up this up, it was also added to gitignore to help prevent accidenntl disclosure

requirements.txt
- as I made changes it required more libraries and a requirementsfile became more nescessary
- Readme was updated to reflect this difference in running

Add Color/Cleanup Output
- I felt like some of the comments hinged around more readable output, so I added some colors to make it easier for the eye to seperate.
- when it was a single IP I felt it was ok, but viewing results for multiple IP's was taxing and needed more seperation.