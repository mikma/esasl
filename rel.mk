libsubdir = $(ERLANG_INSTALL_LIB_DIR)/$(OPT_APP)-$($(OPT_APP)_VSN)
bindir = $(libsubdir)/bin
ebindir = $(libsubdir)/ebin
incdir = $(libsubdir)/include

ebin_DATA = $(OPT_APP:=.boot)
EXTRA_DIST = ../src/$(OPT_APP:=.rel.in)
CLEANFILES = $(OPT_APP:=.boot) $(OPT_APP:=.rel) $(OPT_APP:=.script)

include $(top_srcdir)/rules.mk
