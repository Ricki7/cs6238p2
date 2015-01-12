=====================================================
 README:
=====================================================

#Run the project in run folder.
#All source code is in the source_code folder.
#A stripped down version of this project is located in basic_version and was used for timing. 

To Compile:
1. Navigate a console to the run folder and execute: 
java -jar SDDR_Server.jar

2. Open a new console, navigate to the run folder and execute: 
java -jar SDDR_Client.jar

3. Type in the username 'client' and the password 'client'
4. Copy & paste the below commands  into the client window:

start-session(localhost)
put(test1, none)
put(test2, integrity)
put(test3, confidential)
put(test4, none)
put(test5, none)
delegate(test1, client2, 1000000, true, both)
delegate(test2, client2, 10000, true, get)
delegate(test3, client2, 10000, false, put)
delegate(test4, all, 10000, false, put)
delegate(test5, client2, 1, true, get)
end-session
exit

5. Run SDDR_Client again
6. Type in the username 'client2' and password 'client2'
7. Copy & paste the below commands:

start-session(localhost)
get(565872A88E2A8ECBC2ED28FEEF7A4146BCF15347)
get(80494E806F28DB7842E7CE6AF8552A5B24C49E7B)
get(77540B3E4CC662BD45A93FDA72A9F3C251AFB23B)
get(FA5456882457803DAD819089B0C5CC57D0324641)
put(565872A88E2A8ECBC2ED28FEEF7A4146BCF15347, none)
put(80494E806F28DB7842E7CE6AF8552A5B24C49E7B, integrity)
delegate(test1, client3, 1000, true, both)
delegate(test2, client3, 1000, false, get)
delegate(test2, client3, 1000, false, put)
delegate(test3, client3, 1000, false, both)
delegate(test5, client3, 1000, false, get)

*These commands test all functions, delegations, and access rights*
10. Modify the server file 565872A88E2A8ECBC2ED28FEEF7A4146BCF15347
11. Execute the below command to verify integrity:

get(80494E806F28DB7842E7CE6AF8552A5B24C49E7B)

13. Modify 565872A88E2A8ECBC2ED28FEEF7A4146BCF15347 located in client2
14. Execute the below command to verify upload of changed files on end-session
 
end-session
exit
