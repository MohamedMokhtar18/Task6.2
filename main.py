from stix2.v20 import AttackPattern
from stix2 import Filter
from stix2 import MemoryStore
from random import *
techniques = {
   "execution",
   "credential-access",
   "persistence",
   "defense-evasion",
   "privilege-escalation",
   "exfiltration",
   "impact",
   "lateral-movement",
   "discovery",
   "collection",
   "resource-development",
   "reconnaissance",
   "command-and-control",
   "initial-access",
}
#!create a file to put the techtique
file = open("demofile3.txt", "w")
file.write('')
file = open("demofile3.txt", "a")

src = MemoryStore()
src.load_from_file("enterprise-attack.json")
def get_tactic_techniques(thesrc, tactic):
    # double checking the kill chain is MITRE ATT&CK
    # note: kill_chain_name is different for other domains:
    #    - enterprise: "mitre-attack"
    #    - mobile: "mitre-mobile-attack"
    #    - ics: "mitre-ics-attack"
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])
#!iterate for all tactics to get a random technique 
for item in techniques:
    rand = randint(1, 100)
    x=get_tactic_techniques(src, item)
    try:
        thisdict=dict(x[rand])
        urldict=thisdict["external_references"]
        str(x[rand])
        file.write('first technique of tactic '+item+' '+thisdict["name"]+' '+str(urldict[0]['external_id'])+'\n')
    except :
        rand=0
        thisdict=dict(x[rand])
        urldict=thisdict['external_references']
        # str(x[rand])
        file.write('first technique of tactic '+item+' '+thisdict["name"]+' '+str(urldict[0]['external_id'])+'\n')
        pass
    # rand = randint(1, 100)
    # x=get_tactic_techniques(src,item)  
    # try:
    #     str(x[rand])
    # except :
    #     rand=0
    #     pass
    # # x=get_tactic_techniques(src, item)
    # file.write('first technique of tactic '+item+'\n'+str(x[0])+'\n')
    # print(x[rand])
     
