with-int
--------

A host object can have multiple interfaces, and when referenced in a
policy/group, /32s of the interface IP addresses are also used for
address matching.

fw1rules has some support for router/gateway/host objects with
multiple IP addresses when using the --with_interfaces option.  I have
modified it to also place the space separated list of interface IP
addresses in the 'members' field of the --dump_objects_tsv file.


service-enhancements
--------------------

fw1rules did not support protocol numbers for "Other" services, Type and Code for ICMP services, program numbers for RPC services, or UUID for DCERPC services. Also no custom timeout where printed out.

The output format of --dump_rules_tsv was not changed so that no compatibility issues arise for tools building on top of that output. Instead two new columns are available via templates: <<<timeout>>><TAB><<<protocol>>>. The program number(s) for RPC service, the UUID for DCERPC are printed in the <<<port>>> column and the Type of ICMP is printed into <<<sportfrom>>> while the Code is printed into <<<sportto>>>.

A template example is attached

--template=services-ns.tsv --output=services.txt


Implicit NAT rules
------------------

Previously implicit NAT rules were only printed with the --with_implicit_rules knob and only if the object is also referenced within the ACL rule base as well. The ACL rule base could reference a network or a range object or a object under a different name or simple Any, which also would be a valid match for an implicit NAT rule. However, the NAT rule under those circumstances was only printed when --all_objects was used. Under this case all objects and not just objects with NAT where printed. The behavior was changed so that when --with_implicit_rules is selected and an object has a NAT address configured, then this object is automatically handled as used even if it may not be named in the ACL rule base. 


Comment fix for R65
-------------------

R65 has two fields for a comment: A rule name and a comment. In previous code when neither value exist an orphan reference was printed. The fix only prints the rule name or comment if one or the other or both exist. Both are written into the comment column separated by a "-".

Example: "Rule name - this is the comment", or "there is just a name", or "there is just a comment"
