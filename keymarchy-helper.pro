# The privileged helper links QtCore only, so little code runs as root.
QT = core
CONFIG += c++17 release
TARGET = keymarchy-helper
TEMPLATE = app
HEADERS += src/enroll.h src/registry.h src/store.h
SOURCES += src/helper.cpp src/enroll.cpp src/registry.cpp src/store.cpp
