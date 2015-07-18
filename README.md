# Hyperthreat Demo Set-Up

This document describes how the Demo works

# Demo Data

The demo is based on the DARPA R6.1 sample Dataset. We have used the TA-insiderthreat add-on for field extractions. 

Inside this data set, for this demo we focus on the insider R6.1-1

Excerpt from answers.tar.bz2/insiders.csv:

  `dataset	scenario	details	user	start	end`  
  
  `6.1	1	r6.1-1.csv	CSF2712	01/06/2011 04:51:28	01/12/2011 01:06:22`  

Within this dataset we try to detect malicious activity. Excerpt from answers.tar.bz2/r6.1-1.csv:

  `device	{U4Z2-C3PG35WE-4721OTVQ}	01/06/2011 05:12:15	CSF2712	PC-3343	R:\;R:\CSF2712  `
  `file	{Z9V2-I8MN09XB-3302UJCM}	01/06/2011 05:22:43	CSF2712	PC-3343	R:\NLAGPC6N.jpg  `  
  
  `device	{G2O6-E4CC73XL-3643FCIX}	01/06/2011 05:26:22	CSF2712	PC-3343	 `
  
  `logon	{K3D7-A8HT60QM-7452TTTO}	01/06/2011 05:27:22	CSF2712	PC-3343	Logoff  `
  
  `logon	{E6L5-Q2KP67MT-1441FXAD}	01/08/2011 05:57:25	CSF2712	PC-3343	Logon  `
  
  `device	{P1V7-M2DN59BV-2683AGJH}	01/08/2011 05:59:01	CSF2712	PC-3343	R:\;R:\CSF2712  `
  
  `file	{V8Y5-Y7OI30GO-5400AJZP}	01/08/2011 06:07:21	CSF2712	PC-3343	R:\NLAGPC6N.jpg  `
  .
  .
  .

# Challenges

Because the test data was only available as historical data, we had to simulate schedule the alert in current time, but look at the historical timeranges.
As we use Baselining functionality, this boiles down having two searches for each of the risk events. In production
there would only be one baselining search and one alert search, for each risk event type and these would run on schedule constantly.

# Search Setup
## Baselining Searches
All the baselining searches in this demo are set up similarly

`Line 1: index="insiderthreat" sourcetype="insiderthreat:logon" starttime="12/07/2010:00:00:00" endtime="01/06/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday") `

Line 1: Search for login events during off-working hours over a timeperiod of 4 weeks (learning phase) before risk event happens

`Line 2: | bucket span=1d _time `

Line 2: Bucket the events into 1 day buckets

`Line 3: | chart limit=0 dc(user) as count over _time by user `

Line 3: Count wether a user has logged in at a particular day 

`Line 4: | makecontinuous _time span=1d `

Line 4: If we have missing days (no events) in the data, fill up these days

`Line 5: | fillnull `

Fill up empty columsn with 0

`Line 6: | untable _time, user, count `

Bring the table into a format that is suitable for baselining

`Line 7: | fillbaseline config_name="r6.1-1-1" value=user count`

Fill the baseline into a KV Store named r6.1-1-1 and tell the baselining algorithm to baseline the user's logon count

## Alert Searches

All alert searches follow a similar pattern.

`Line 1: search = index="insiderthreat" sourcetype="insiderthreat:logon" starttime="01/06/2011:00:00:00" endtime="01/07/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday")`

Line 1: Search for login events during off-working hours over a particular day

`Line 2:  | stats dc(user) as count earliest(_time) as _time earliest(_raw) as _raw by user`

Line 2: Count if the user had a login that day

`Line 3:  | comparetobaseline config_name="r6.1-1-1" value=user count`

Line 3: Compare to the baseline using the KV store previously defined. Tell to look at the count values of the user field.

`Line 4: | search count:score=1`

Line 4: If a user has more logins than usualy, we get a score=1 back. A score of 0 would be ok. A score of -1 would mean, this was the users first login (user not found in the baseline).

`Line 5: | table _time, _raw, user`

Line 5: Select the columns to display and possibly store as contributing data.


## Encryption

We have added a version of the searches that encrypts the data on the fly. There are two macros be have created

### Macro "create_user_hash"

`Line 1: eval user_hash=user`

Line 1: Create a field user_hash to store the hash of the user 

`Line 2: | hash algorithm=sha256 saltfile=/opt/splunk/etc/auth/splunk.secret user_hash `

Line 2: Hash the user_hash field with sha256 and using the splunk.secret file as a salt.

### Macro "encrypt_user_raw"

`Line 1: crypt mode=e key=/opt/splunk/etc/apps/SA-hypercrypto/lib/public.pem user _raw`

Line 1: Encrypt the user and the _raw fields using a specified public key

`Line 2: | eval decrypt_command="crypt mode=d key=/opt/splunk/etc/apps/SA-hypercrypto/lib/private.pem user _raw" `

Line 2: Add a note field "decrypt_command" to store the command about how to decrypt the data

### How to use these macros

The macros can easily be integrated into the non-encrypted versions:

### Hashing Baselining search

`index="insiderthreat" sourcetype="insiderthreat:logon" starttime="12/07/2010:00:00:00" endtime="01/06/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday") | bucket span=1d _time | chart limit=0 dc(user) as count over _time by user | makecontinuous _time span=1d | fillnull | untable _time, user, count | 'create_user_hash'  | fillbaseline config_name="r6.1-1-1-encrypted" value=user_hash count`

### Hashing and Encrypting Risk Alert Search

`index="insiderthreat" sourcetype="insiderthreat:logon" starttime="01/06/2011:00:00:00" endtime="01/07/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday") | stats dc(user) as count earliest(_time) as _time earliest(_raw) as _raw by user | 'create_user_hash'  |comparetobaseline config_name="r6.1-1-1-encrypted" value=user_hash count |search count:score=1 |table _time, _raw, user, user_hash | 'encrypt_user_raw' `

# Risk Manager Setup

## Base Setup

- A role "riskanalyzer" has been created. This role imports the role "risk_manager" and "can_encrypt"
- A role "hrlegal" has been created. This role imports the role "risk_manager" and "can_decrypt". The role does not have any access to indexes
- All alert searches needed are calling the risk_handler.py alert script
- All alert searches run under a user that has the role "risk_detecter"



