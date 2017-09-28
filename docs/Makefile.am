doxy.stamp:
	$(DOXYGEN) $(builddir)/device-monitor.doxy
	echo > doxy.stamp

CLEANFILES = doxy.stamp

all-local: doxy.stamp

clean-local:
	rm -rf html/
	if test -a "doxygen_sqlite3.db"; then rm doxygen_sqlite3.db; fi

