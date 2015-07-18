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

## Challenges

Because the test data was only available as historical data, we had to simulate schedule the alert in current time, but look at the historical timeranges.
As we use Baselining functionality, this boiles down having two searches for each of the risk events. In production
there would only be one baselining search and one alert search, for each risk event type and these would run on schedule constantly.

## Baselining Searches:
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



