-----------------------------------------------------------------------
			FW1Rules Templates
-----------------------------------------------------------------------

Templates are text files that can be filled with data from the actual
firewall configuration. 

Throughout the template three special characters can be defined:
	<NEWLINE>	translated into the newline character (\n)
	<SPACE>		translated into the space character (\s)
	<TAB>		translated into the tab character (\t)

Each template starts with a header, enclosed in lines consisting of
at least 15 minus signs.

The second line has to start with "title=" and should describe the
template. It is printed when using the --verbose option.

The third line has to start with "separator=" and defines with which
characters members or multiple entries in rules shall be separated.

Example:
	---------------
	title=OBJECTS.TSV - object definitions tab separated
	separator=<SPACE>
	---------------


Consecutive lines starting with five paragraph characters (§§§§§) mark
a block. Each of these blocks will be processed once for (and with)
each object/rule defined in the firewall setting.

Within these blocks (and for some even outside) special variables
marked with three paragraph characters (§§§) will be replaced by the
respective firewall settings. For a complete listing and an
explanation of the individual special variables please have a look at
the template  fullconfig.txt


-----------------------------------------------------------------------
		    Predefined FW1Rules Templates
-----------------------------------------------------------------------

fullconfig.html	Prints all firewall configuration into a HTML file.
		While this is similar to the --output_html option, it
		lacks icons, references and other of the eye-candy
		stuff the command line option - but is easier to
		transfer to people that e.g. do not have the icon
		files. This is *NOT* meant to replace the
		--output_html option. 

fullconfig.txt	Prints all firewall configuration into a text TXT file,
		a no-nonsense and very compatible approach.

baseconfig.tex	Prints the base configuraton (without properties or
		users) into a LaTeX file to give a Postscript or PDF 
		output file. The output is by far not optimum, but I
		did not find a better way to present all the settings
		yet. Anyone help, please?

properties.txt	Just prints the firewall properties and base settings
		into a TXT file



rules.csv	Access rules in a table quote/comma separated

rules.sql	Access rules into a myPHPadmin-like SQL command file

rules.ssv	Access rules in a table semicolon separated

rules.tsv	Access rules in a table tab separated
		Using this is equivalent to  --dump_rules_tsv

rules.txt	Access rules in a plain ASCII file
		Using this is equivalent to  --dump_rules_txt




nat.csv		NAT rules in a table quote/comma separated

nat.ssv		NAT rules in a table semicolon separated

nat.tsv		NAT rules in a table tab separated
		Using this is equivalent to  --dump_nat_tsv

nat.txt		NAT rules in a plain ASCII file
		Using this is equivalent to  --dump_nat_txt


objects.csv	Network Objects in a table quote/comma separated

objects.sql	Network Objects in a myPHPadmin-like SQL command file

objects.ssv	Network Objects in a table semicolon separated

objects.tsv	Network Objects in a table tab separated
		Using this is equivalent to  --dump_objects_tsv

objects.txt	Network Objects in a plain ASCII file
		Using this is equivalent to  --dump_objects_txt


services.csv	Services in a table quote/comma separated

services.sql	Services in a myPHPadmin-like SQL command file

services.ssv	Services in a table semicolon separated

services.tsv	Services in a table tab separated
		Using this is equivalent to  --dump_services_tsv

services.txt	Services in a plain ASCII file
		Using this is equivalent to  --dump_services_txt



