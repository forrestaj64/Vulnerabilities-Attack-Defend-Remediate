## Project_3 / Final Week
Vulnerabilities: Attack, Defend and Remediate 

### Overview 

This week, you will work on your final project by completing the following tasks:

- Implement the alarms and thresholds you determined would be effective in Project 2.

- Assess two more vulnerable VMs and verify that the rules work as expected.

- Use Wireshark to analyze live malicious traffic on the wire.

You will complete each of these activities **individually**. You will then work in groups of three to six to develop presentations for the final day of class. 

### Lab Environment 

This week's lab environment is an Azure Classroom Lab containing a modified version of the Project 2 network. In particular, it includes the following machines:

- **Capstone** (`192.168.1.105`): The vulnerable target VM that you will attack to test alerts. Filebeat and Metricbeat are installed and will forward logs to the ELK machine. 
   - Please note that this VM is in the network solely for the purpose of testing alerts.

- **ELK** (`192.168.1.100`): The same ELK setup that you created in Project 1. It holds the Kibana dashboards.

- **Kali** (`192.168.1.90`): A standard Kali Linux machine for use in the penetration test on Day 1. 
   - Credentials are `root`:`toor`.

- **Target 1** (`192.168.1.110`): Exposes a vulnerable WordPress server.

- **Target 2** (`192.168.1.115`): Exposes the same WordPress site as above, but with better security hardening. It must be exploited differently than Target 1.

### Task Breakdown

The following breakdown describes the tasks you will be assigned and a recommended timeline for achieving each milestone. 

#### Day 1: Target 1

After your instructor reviews the project overview and demonstrates how to use `wpscan` to assess a WordPress target, you will configure alerts in Kibana and test them by repeating attacks against the Capstone VM. Then you will begin your assessment of the first vulnerable VM: Target 1.


#### Day 2: Target 1

On Day 1, you will complete an assessment of Target 1. Those of you who complete this task may move on to the Wireshark analysis.


#### Day 3: Analysis

After assessing the Target 1, you will use the Kali VM to capture and analyze traffic on the virtual network with Wireshark. You will analyze the traffic to explain what users are doing on the network. After analyzing Wireshark traffic, you will spend the remainder of class completing summaries of your work. If all of the above is complete, you may complete the assessment of Target 2. Instruction are available in the Day 1 activity file. 


#### Day 4: Presentations

You will work individually, complete the deliverables of the project, and present your findings to the class in a short presentation (approx. 10 mins). 

