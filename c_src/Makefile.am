VPATH = ../c_src

AM_CFLAGS = -Wall -g -DHAVE_KRB5
AM_CPPFLAGS = $(GSASL_CFLAGS)

privdir = $(ERLANG_INSTALL_LIB_DIR)/esasl-$(VERSION)/priv
priv_PROGRAMS = gsasl_drv

gsasl_drv_LDFLAGS = $(GSASL_LIBS)
gsasl_drv_LDADD = -lei
gsasl_drv_SOURCES = gsasl_drv.c port_util.h port_util.c
