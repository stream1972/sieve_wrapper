#
# Makefile for Linux and other Posix-style platforms
#

# Set to path of Boinc source tree

BOINC_BASE = /home/boincadm/boinc-src

#
# Note on setting up libraries
#
# By default, libraries are used right from Boinc source
#

LIBS_BASE = $(BOINC_BASE)
LIBS      = $(LIBS_BASE)/api/libboinc_api.a $(LIBS_BASE)/lib/libboinc.a

#
# However, it's not good when you need to build both 32-bit and 64-bit versions
# of wrapper, because each of them requires own libraries.
#
# Then, configure and build libraries for each version, and save built libraries
# somewhere else. You need 5 files:
#
#    libboinc_api.a                (from 'api')
#    libboinc.a                    (from 'lib')
#    config.h                      (from project root directory)
#    version.h
#    project_specific_defines.h
#
# Then uncomment LIBS and set LIBS_BASE to correct directory for this platform below.
#

ifdef linux32
target    = linux32
CXXFLAGS += -m32
else ifdef linux64
target    = linux64
CXXFLAGS += -m64
else
$(error Specify linux32=1 or linux64=1 on command line)
endif

#
# Uncomment this to use local copies of libraries for $(target)
# (for example, in /work/boinc-libs/linux32)
#

# LIBS_BASE = /work/boinc-libs/$(target)
# LIBS      = $(LIBS_BASE)/libboinc_api.a $(LIBS_BASE)/libboinc.a

ifdef VERBOSE
CPPFLAGS += -DVERBOSE
endif

obj = output_$(target)
exe = srw_$(target)

CXXFLAGS += -O2 -Wall -Wextra
LDFLAGS  += -s -static
CPPFLAGS += -I$(BOINC_BASE)/api -I$(BOINC_BASE)/lib -I$(LIBS_BASE)

.PHONY: all
all: $(obj) $(exe)

$(obj):
	mkdir $@

$(exe): $(obj)/wrapper.o
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS) $(LIBS) -lpthread

$(obj)/%.o: %.cpp
	$(CXX) -c $< -o $@ $(CPPFLAGS) $(CXXFLAGS)
