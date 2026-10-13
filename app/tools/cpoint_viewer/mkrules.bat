rem !-------------------------------------------------
rem ! Microsoft-Limitation: 
rem !	The MS-DOS command line won't accept more 
rem !	than 9 parameters at once. Use Unix.
rem !-------------------------------------------------

perl fw1rules.pl --verbose --with_implicit_rules --no_users --output_html=rule.html
