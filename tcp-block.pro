TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread

SOURCES += \
	arphdr.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp \
	my-func.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	ip.h \
	iphdr.h \
	mac.h \
	my-func.h \
	tcphdr.h
