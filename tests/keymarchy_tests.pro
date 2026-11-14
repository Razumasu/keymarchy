QT += core gui qml quick quickcontrols2 testlib
CONFIG += c++17 testcase
TARGET = keymarchy_tests
TEMPLATE = app
INCLUDEPATH += ../src
HEADERS += ../src/backend.h ../src/registry.h ../src/store.h ../src/theme.h ../src/translator.h
SOURCES += keymarchy_tests.cpp ../src/backend.cpp ../src/registry.cpp ../src/store.cpp ../src/theme.cpp ../src/translator.cpp
RESOURCES += ../src/resources.qrc

CONFIG += link_pkgconfig
PKGCONFIG += libfido2
HEADERS += ../src/presence.h
SOURCES += ../src/presence.cpp
