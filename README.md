# Hyperthreat Demo Set-Up

This document describes how the Demo works

# Demo Data

- The demo is based on the DARPA R6.1 sample Dataset. We have used the TA-insiderthreat add-on for field extractions. 

- Inside this data set, for this demo we focus on the insider R6.1-1

- Excerpt from answers.tar.bz2/insiders.csv:

  `dataset	scenario	details	user	start	end`  
  
  `6.1	1	r6.1-1.csv	CSF2712	01/06/2011 04:51:28	01/12/2011 01:06:22`  

- Within this dataset we try to detect malicious activity. Excerpt from answers.tar.bz2/r6.1-1.csv:

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
As we use Baselining functionality, this boiles down having two searches for each of the risk events. In production there would only be one baselining search and one alert search, for each risk event type and these would run on schedule constantly.

# Search Setup
## Baselining Searches
- All the baselining searches in this demo are set up similarly

`Line 1: index="insiderthreat" sourcetype="insiderthreat:logon" starttime="12/07/2010:00:00:00" endtime="01/06/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday") `

Search for login events during off-working hours over a timeperiod of 4 weeks (learning phase) before risk event happens

`Line 2: | bucket span=1d _time `

Bucket the events into 1 day buckets

`Line 3: | chart limit=0 dc(user) as count over _time by user `

Count wether a user has logged in at a particular day 

`Line 4: | makecontinuous _time span=1d `

If we have missing days (no events) in the data, fill up these days

`Line 5: | fillnull `

Fill up empty columsn with 0

`Line 6: | untable _time, user, count `

Bring the table into a format that is suitable for baselining

`Line 7: | fillbaseline config_name="r6.1-1-1" value=user count`

Fill the baseline into a KV Store named r6.1-1-1 and tell the baselining algorithm to baseline the user's logon count

## Alert Searches

- All alert searches follow a similar pattern.

`Line 1: search = index="insiderthreat" sourcetype="insiderthreat:logon" starttime="01/06/2011:00:00:00" endtime="01/07/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday")`

Search for login events during off-working hours over a particular day

`Line 2:  | stats dc(user) as count earliest(_time) as _time earliest(_raw) as _raw by user`

Count if the user had a login that day

`Line 3:  | comparetobaseline config_name="r6.1-1-1" value=user count`

Compare to the baseline using the KV store previously defined. Tell to look at the count values of the user field.

`Line 4: | search count:score=1`

If a user has more logins than usualy, we get a score=1 back. A score of 0 would be ok. A score of -1 would mean, this was the users first login (user not found in the baseline).

`Line 5: | table _time, _raw, user`

Select the columns to display and possibly store as contributing data.


## Encryption

We have added a version of the searches that encrypts the data on the fly. There are two macros be have created

### Macro "create_user_hash"

`Line 1: eval user_hash=user`

Line 1: Create a field user_hash to store the hash of the user 

`Line 2: | hash algorithm=sha256 saltfile=/opt/splunk/etc/auth/splunk.secret user_hash `

Line 2: Hash the user_hash field with sha256 and using the splunk.secret file as a salt.

### Macro "encrypt_user_raw"

`Line 1: crypt mode=e key=/opt/splunk/etc/apps/SA-hypercrypto/lib/public_aes256.pem user _raw`

Line 1: Encrypt the user and the _raw fields using a specified public key

`Line 2: | eval decrypt_command="crypt mode=d key=/opt/splunk/etc/apps/SA-hypercrypto/lib/private_aes256.pem user _raw" `

Line 2: Add a note field "decrypt_command" to store the command about how to decrypt the data

### How to use these macros

The macros can easily be integrated into the non-encrypted versions:

### Hashing Baselining search

`index="insiderthreat" sourcetype="insiderthreat:logon" starttime="12/07/2010:00:00:00" endtime="01/06/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday") | bucket span=1d _time | chart limit=0 dc(user) as count over _time by user | makecontinuous _time span=1d | fillnull | untable _time, user, count | 'create_user_hash'  | fillbaseline config_name="r6.1-1-1-encrypted" value=user_hash count`

### Hashing and Encrypting Risk Alert Search

`index="insiderthreat" sourcetype="insiderthreat:logon" starttime="01/06/2011:00:00:00" endtime="01/07/2011:00:00:00" action=Logon (date_hour>=20 OR date_hour<=6) OR (date_wday="saturday" OR data_wday="sunday") | stats dc(user) as count earliest(_time) as _time earliest(_raw) as _raw by user | 'create_user_hash'  |comparetobaseline config_name="r6.1-1-1-encrypted" value=user_hash count |search count:score=1 |table _time, _raw, user, user_hash | 'encrypt_user_raw' `

# Risk Manager Setup

## Base Setup

- A role "riskanalyzer" has been created. This role imports the role "risk_manager". The role has no access to any indexes. The role is assigned to an employee that does the initial analysis, and is not allowed to see all details
- A role "hrlegal" has been created. This role imports the role "risk_manager" and "can_decrypt". The role does not have any access to indexes. The role is assigned to an employee who has the right to see all the data.
- A role "riskdetector" as been created. This role has access to the index insiderthreats and can see raw events. The role inherits the role "can_encrypt". This role is used to run the risk event alert searches.
- All alert searches needed are calling the risk_handler.py alert script
- All alert searches run under the user "riskdetector" that has the role "riskdetector"
- A user "riskanalyzer" is created with the role riskanalyzer
- A user "riskdetector" is created with the role riskdetector
- A user "hrlegal" is created with the role hrlegal. This user has also stored the password for the private key "private_aes256.pem" in the Splunk keystore.
- Under the risk score settings dashboard,we assign two score points to all risk alert searches, except the ones, where the baseline compare-search says, that a user did something for the first time. Here we assign only one point.

# Risk Analysis Dashboards (Things you should try...)
- After the baselining searches and alert searches are run, the dashboards should fill up, and reveal two risk object, "user" and "user_hash"
- The "user" CSF2712 should be on top of the risk object list together with another user_hash user, that is the same user, but with the hashed username.
- Drilling down, by clicking on the user_hash risk object. Should finally reveal the user's real name and unencrypted _raw events under "Risk Details Decrypted".
- The Risk Analyzer dashboard should show also show you, that the User CSF2712 (and its hashed counterpart) has accumulated most of the scores.
- Use the risk score tuner dashboard to reset a risk score and check, how the risk analyzer dashboard and risk search dashboard will show this reset event.
- Assign the "can_decrypt" -role to someone else than the "hrlegal" user, and try to decrypt the data. This will fail, as the private key is password protected and is not stored in the keystore.

