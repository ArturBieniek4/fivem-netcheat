TEMPLATE = app
TARGET = qt_event_inspector

QT += core gui widgets
CONFIG += c++17

INCLUDEPATH += src

SOURCES += \
    src/main.cpp \
    src/mainwindow.cpp \
    src/eventmodel.cpp \
    src/editdialog.cpp \
    src/dummyeventsource.cpp

HEADERS += \
    src/mainwindow.h \
    src/eventmodel.h \
    src/editdialog.h \
    src/dummyeventsource.h \
    src/eventtypes.h
