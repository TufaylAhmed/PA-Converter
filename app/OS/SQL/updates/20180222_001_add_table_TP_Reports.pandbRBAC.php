CREATE TABLE `TP_Reports` (
`id` int(11) NOT NULL AUTO_INCREMENT,
`name` varchar(255) NOT NULL,
`type` varchar(150) NOT NULL,
`data` text,
`query` text,
`repeated` text,
`description` varchar(255) NOT NULL,
`direction` varchar(150) NOT NULL,
`panos` varchar(45) NOT NULL,
`version` int(11) NOT NULL,
PRIMARY KEY (`id`),
UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Non-Working-Traffic','reports','<entry name="Inbound Non-Working-Traffic">
    <type>
        <panorama-traffic>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>srcloc</member>
                <member>from</member>
                <member>to</member>
                <member>app</member>
                <member>dport</member>
                <member>non-std-dport</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-calendar-day</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound Non-Working-Traffic</caption>
    <description>Optional: What is trying to access internal servers. Not scheduled.</description>
</entry>','((app eq incomplete) or (app eq insufficient-data) or (app eq not-applicable) or (action eq deny) or (action eq drop))','','','inbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Outbound Non-Working-Traffic','reports','<entry name="Outbound Non-Working-Traffic">
    <type>
        <panorama-traffic>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>srcloc</member>
                <member>from</member>
                <member>to</member>
                <member>app</member>
                <member>dport</member>
                <member>non-std-dport</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-calendar-day</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Outbound Non-Working-Traffic</caption>
    <description>Optional: What is trying to access Internet servers. Not scheduled.</description>
</entry>','((app eq incomplete) or (app eq insufficient-data) or (app eq not-applicable) or (action eq deny) or (action eq drop))','','','outbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Used Rules','reports','<entry name="Inbound Used Rules">
    <type>
        <panorama-traffic>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>rule</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound Used Rules</caption>
    <frequency>daily</frequency>
    <description>All Inbound Used Rules. Use to determine what rules are NOT used.</description>
</entry>','(action eq allow) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','','inbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal Used Rules','reports','<entry name="Internal Used Rules">
    <type>
        <panorama-traffic>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>rule</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Internal Used Rules</caption>
    <frequency>daily</frequency>
    <description>All Internal Used Rules. Use to determine what rules are NOT used.</description>
</entry>','(action eq allow) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','','internal','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Outbound Used Rules','reports','<entry name="Outbound Used Rules">
    <type>
        <panorama-traffic>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>rule</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Outbound Used Rules</caption>
    <frequency>daily</frequency>
    <description>All Outbound Used Rules. Use to determine what rules are NOT used.</description>
</entry>','(action eq allow) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','','outbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Used Rules','reports','<entry name="Used Rules">
    <type>
        <panorama-traffic>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>rule</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Used Rules</caption>
    <frequency>daily</frequency>
    <description>All Used Rules. Use to determine what rules are NOT used.</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','','global','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Outbound File DNLD by Rule','reports','<entry name="Outbound File DNLD by Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Outbound File DNLD by Rule</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-data>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>threatid</member>
                <member>from</member>
                <member>to</member>
                <member>direction</member>
                <member>app</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-data>
    </type>
    <description>Internal Network Downloading Files From the Internet</description>
</entry>','(action eq alert) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (direction eq server-to-client)','','','outbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound File UPLD by Rule','reports','<entry name="Inbound File UPLD by Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound File UPLD by Rule</caption>
    <type>
        <panorama-data>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>threatid</member>
                <member>srcloc</member>
                <member>from</member>
                <member>to</member>
                <member>dst</member>
                <member>direction</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-data>
    </type>
    <frequency>daily</frequency>
    <description>Internet Clients Uploading Files to your network</description>
</entry>','(action eq alert) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (direction eq client-to-server)','','','inbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal File UPLD by Rule','reports','<entry name="Internal File UPLD by Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Internal File UPLD by Rule</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-data>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>threatid</member>
                <member>srcloc</member>
                <member>from</member>
                <member>to</member>
                <member>dst</member>
                <member>direction</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-data>
    </type>
    <description>Files uploaded Internal to Internal</description>
</entry>','(action eq alert) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (direction eq client-to-server)','','','internal','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Source Countries','reports','<entry name="Inbound Source Countries">
    <type>
        <panorama-traffic>
            <sortby>bytes</sortby>
            <aggregate-by>
                <member>srcloc</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>10</topm>
    <caption>Inbound Source Countries</caption>
    <frequency>daily</frequency>
    <description>Source Countries initiating successful connections</description>
</entry>','(action eq allow) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','','inbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Source Countries-App','reports','<entry name="Inbound Source Countries-App">
    <type>
        <panorama-traffic>
            <sortby>bytes</sortby>
            <group-by>srcloc</group-by>
            <aggregate-by>
                <member>container-of-app</member>
                <member>app</member>
            </aggregate-by>
            <values>
                <member>bytes</member>
                <member>repeatcnt</member>
            </values>
        </panorama-traffic>
    </type>
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound Source Countries-App</caption>
    <frequency>daily</frequency>
    <description>Source Countries initiating successful connections to your network and the Apps they are using</description>
</entry>','(action eq allow) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','','inbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Allowd Viruses','reports','<entry name="Inbound Allowd Viruses">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>10</topm>
    <caption>Inbound Allowd Viruses</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>threatid</member>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>app</member>
                <member>direction</member>
                <member>severity</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Viruses allow into your network from the Internet</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and ((action eq alert) or (action eq allow)) and ((subtype eq virus) or (subtype eq wildfire-virus))','([INBOUND] and (direction eq client-to-server)) or ([OUTBOUND] and (direction eq server-to-client))','','inbound,outbound','8','1');


INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Denied Viruses','reports','<entry name="Inbound Denied Viruses">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>10</topm>
    <caption>Inbound Denied Viruses</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>threatid</member>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>app</member>
                <member>direction</member>
                <member>severity</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Viruses successfully denied from entering your network</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and ((action neq alert) and (action neq allow)) and ((subtype eq virus) or (subtype eq wildfire-virus))','([INBOUND] and (direction eq client-to-server)) or ([OUTBOUND] and (direction eq server-to-client))','','inbound,outbound','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal Allowd Viruses','reports','<entry name="Internal Allowd Viruses">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>10</topm>
    <caption>Internal Allowd Viruses</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>threatid</member>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>app</member>
                <member>direction</member>
                <member>severity</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Viruses allow into your network from your network (lateral movement).</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and ((action eq alert) or (action eq allow)) and ((subtype eq virus) or (subtype eq wildfire-virus))','','','internal','8','1');



INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal Denied Viruses','reports','<entry name="Internal Denied Viruses">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>10</topm>
    <caption>Internal Denied Viruses</caption>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <aggregate-by>
                <member>threatid</member>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>app</member>
                <member>direction</member>
                <member>severity</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <frequency>daily</frequency>
    <description>Viruses successfully denied from traveling laterally</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and ((action neq alert) and (action neq allow)) and ((subtype eq virus) or (subtype eq wildfire-virus))','','','internal','8','1');


INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Rules wThreat','reports','<entry name="Inbound Rules wThreat">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound Rules wThreat</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>threatid</member>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>app</member>
                <member>direction</member>
                <member>severity</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Inbound Rules allowing or denying viruses, spyware and vulnerabilities.</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','([INBOUND] and (direction eq client-to-server)) or ([OUTBOUND] and (direction eq server-to-client))','','inbound','8','1');


INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal Rules wThreat','reports','<entry name="Internal Rules wThreat">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Internal Rules wThreat</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>threatid</member>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>app</member>
                <member>direction</member>
                <member>severity</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Internal Rules allowing or denying viruses, spyware and vulnerabilities.</description>
</entry>','((direction eq server-to-client) or (direction eq client-to-server)) and (app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable)','','internal','8','1');


INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Allowd Spyware Rule','reports','<entry name="Inbound Allowd Spyware Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound Allowd Spyware Rule</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>threatid</member>
                <member>category-of-app</member>
                <member>app</member>
                <member>dport</member>
                <member>direction</member>
                <member>severity</member>
                <member>misc</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Spyware allowed in from the Internet</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (subtype eq spyware) and ((action eq alert) or (action eq allow))','([INBOUND] and (direction eq client-to-server)) or ([OUTBOUND] and (direction eq server-to-client))','','inbound,outbound','8','1');


INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Inbound Denied Spyware Rule','reports','<entry name="Inbound Denied Spyware Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Inbound Denied Spyware Rule</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>threatid</member>
                <member>category-of-app</member>
                <member>app</member>
                <member>dport</member>
                <member>direction</member>
                <member>severity</member>
                <member>misc</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Spyware successfully blocked from entering your network</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (subtype eq spyware) and ((action neq alert) and (action neq allow))','([INBOUND] and (direction eq client-to-server)) or ([OUTBOUND] and (direction eq server-to-client))','','inbound,outbound','8','1');


INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal Allowd Spyware Rule','reports','<entry name="Internal Allowd Spyware Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Internal Allowd Spyware Rule</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>threatid</member>
                <member>category-of-app</member>
                <member>app</member>
                <member>dport</member>
                <member>direction</member>
                <member>severity</member>
                <member>misc</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Spyware allowed laterally</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (subtype eq spyware) and ((action eq alert) or (action eq allow))','','','internal','8','1');

INSERT INTO TP_Reports (name,type,data,query,repeated,description,direction,panos,version) VALUES ('Internal Denied Spyware Rule','reports','<entry name="Internal Denied Spyware Rule">
    <period>last-30-calendar-days</period>
    <topn>500</topn>
    <topm>50</topm>
    <caption>Internal Denied Spyware Rule</caption>
    <frequency>daily</frequency>
    <type>
        <panorama-threat>
            <sortby>repeatcnt</sortby>
            <group-by>rule</group-by>
            <aggregate-by>
                <member>category-of-threatid</member>
                <member>subtype</member>
                <member>threatid</member>
                <member>category-of-app</member>
                <member>app</member>
                <member>dport</member>
                <member>direction</member>
                <member>severity</member>
                <member>misc</member>
                <member>action</member>
            </aggregate-by>
            <values>
                <member>repeatcnt</member>
            </values>
        </panorama-threat>
    </type>
    <description>Spyware successfully denied laterally.  Still investigate for possible infection.</description>
</entry>','(app neq insufficient-data) and (app neq incomplete) and (app neq not-applicable) and (subtype eq spyware) and ((action eq alert) or (action eq allow))','([INBOUND]) or ([OUTBOUND] ) or ([INTERNAL])','','inbound,outboud,internal','8','1');


