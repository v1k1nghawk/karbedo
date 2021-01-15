#-------------------------------------------------
#
# Project created by QtCreator 2020-06-30T16:36:50
#
#-------------------------------------------------

QT       += core gui concurrent

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = karbedo
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    user.cpp \
    collisionAttackTask_CPU.cpp \
    guiupdater.cpp

HEADERS  += mainwindow.h \
    user.h \
    general.h \
    collisionAttackTask_CPU.h \
    guiupdater.h \
    karbedo_app.h \
    parsingexception.h

FORMS    += mainwindow.ui

CONFIG += c++11

QT_OPENGL = opengl

LIBS += -lcrypt
