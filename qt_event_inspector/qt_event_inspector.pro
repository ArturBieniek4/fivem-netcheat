TEMPLATE = app
TARGET = qt_event_inspector

QT += core gui widgets network
CONFIG += c++17

INCLUDEPATH += src

SOURCES += \
    src/main.cpp \
    src/mainwindow.cpp \
    src/eventmodel.cpp \
    src/editdialog.cpp \
    src/dummyeventsource.cpp \
    src/sniffereventsource.cpp

HEADERS += \
    src/mainwindow.h \
    src/eventmodel.h \
    src/editdialog.h \
    src/dummyeventsource.h \
    src/eventtypes.h \
    src/sniffereventsource.h
