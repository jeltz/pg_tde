# Fetches typedefs list for PostgreSQL core and merges it with typedefs defined in this project.
# https://wiki.postgresql.org/wiki/Running_pgindent_on_non-core_code_or_development_code
update-typedefs:
	(wget -q -O - "https://buildfarm.postgresql.org/cgi-bin/typedefs.pl?branch=REL_17_STABLE"; wget -q -O - "https://buildfarm.postgresql.org/cgi-bin/typedefs.pl?branch=REL_18_STABLE") | cat - typedefs.list | sort -u > typedefs-full.list

# Indents projects sources.
indent:
	pgindent --typedefs=typedefs-full.list --excludes=pgindent_excludes .

.PHONY: update-typedefs indent
