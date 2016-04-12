TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += main.cpp

HEADERS += \
    libnet/libnet-asn1.h \
    libnet/libnet-functions.h \
    libnet/libnet-headers.h \
    libnet/libnet-macros.h \
    libnet/libnet-structures.h \
    libnet/libnet-types.h
