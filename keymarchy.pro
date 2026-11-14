QT += core gui qml quick quickcontrols2
CONFIG += c++17 release
TARGET = keymarchy
TEMPLATE = app
HEADERS += src/backend.h src/registry.h src/store.h src/theme.h src/translator.h
SOURCES += src/main.cpp src/backend.cpp src/registry.cpp src/store.cpp src/helper.cpp src/theme.cpp src/translator.cpp
RESOURCES += src/resources.qrc

CONFIG += link_pkgconfig
PKGCONFIG += libfido2
HEADERS += src/presence.h
SOURCES += src/presence.cpp
