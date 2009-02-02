INCLUDES = -I$(includedir) $(GNOME_INCLUDEDIR) $(PISOCK_INCLUDEDIR)

strip_accounts_conduitdir=$(libdir)/gnome-pilot/conduits

strip_accounts_conduit_LTLIBRARIES = libstrip-accounts-conduit.la

libstrip_accounts_conduit_la_SOURCES = strip-accounts-conduit.c  \
	strip-conduit-capplet.h

libstrip_accounts_conduit_la_LIBADD = $(PISOCK_LIBDIR) $(PISOCK_LIBS) \
	$(GNOME_LIBDIR) $(GNOME_LIBS) -lgdbm

bin_PROGRAMS = strip-conduit-control-applet

strip_conduit_control_applet_SOURCES = strip-conduit-capplet.c \
	strip-conduit-capplet.h

strip_conduit_control_applet_LDADD = \
		$(GNOME_CAPPLET_LIBS)  \
		$(GNOME_LIBDIR) \
		$(GNOME_PILOT_LIBS) \
		$(GNOME_CAPPLET_LIBS) \
		$(GNOME_XML_LIB) \
	        $(GNOMEUI_LIBS) \
		$(PISOCK_LIBDIR) $(PISOCK_LIBS) \
                $(INTLLIBS) 

strip.conduit:	strip.conduit.in Makefile
	sed -e 's^\@prefix\@^$(prefix)^g' < $(srcdir)/strip.conduit.in > strip.conduit.tmp \
	&& mv strip.conduit.tmp strip.conduit

ccenterdir = $(datadir)/control-center
ccenterPalmPilotdir = $(ccenterdir)/Peripherals/PalmPilot
ccenterConduitsdir = $(ccenterPalmPilotdir)/Conduits
ccenterConduits_DATA = strip-conduit.desktop

Conduitsdir = $(datadir)/gnome-pilot/conduits/
Conduits_DATA = strip.conduit

EXTRA_DIST = \
	$(Conduits_DATA) \
        $(ccenterConduits_DATA)

install-data-local:
	$(mkinstalldirs) $(Conduitsdir)
	$(mkinstalldirs) $(ccenterConduitsdir)

