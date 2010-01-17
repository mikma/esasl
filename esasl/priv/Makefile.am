VPATH = $(top_srcdir)/esasl/c_src

AM_CFLAGS = -Wall -g
AM_CPPFLAGS = $(GSASL_CFLAGS) $(EI_CFLAGS)

privdir = $(ERLANG_INSTALL_LIB_DIR)/esasl-$(VERSION)/priv
priv_PROGRAMS = gsasl_drv

gsasl_drv_LDFLAGS = $(GSASL_LIBS) $(EI_LDFLAGS)
gsasl_drv_LDADD = $(EI_LIBS)
gsasl_drv_SOURCES = gsasl_drv.c port_util.h port_util.c
