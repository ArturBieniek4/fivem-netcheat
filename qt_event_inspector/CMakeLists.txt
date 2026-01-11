cmake_minimum_required(VERSION 3.16) project(EventInspectorQt LANGUAGES CXX)

    set(CMAKE_CXX_STANDARD 17) set(CMAKE_CXX_STANDARD_REQUIRED ON)

#Enable Qt meta - object compiler, even for Qt5.
        set(CMAKE_AUTOMOC ON) set(CMAKE_AUTOUIC ON) set(CMAKE_AUTORCC ON)

#Prefer Qt6, but allow Qt5.
            find_package(Qt6 COMPONENTS Widgets Network QUIET) if (Qt6_FOUND)
                set(QT Qt6) else() find_package(
                    Qt5 REQUIRED COMPONENTS Widgets Network) set(QT Qt5) endif()

                    if (QT STREQUAL "Qt6") qt_standard_project_setup() endif()

                        set(SOURCES src / main.cpp src / mainwindow.cpp src /
                            eventmodel.cpp src / editdialog.cpp src /
                            dummyeventsource.cpp src / sniffereventsource.cpp)

                            set(HEADERS src / mainwindow.h src /
                                eventmodel.h src / editdialog.h src /
                                eventtypes.h src / dummyeventsource.h src /
                                sniffereventsource.h)

                                add_executable(EventInspectorQt ${SOURCES} ${
                                    HEADERS})

                                    target_link_libraries(
                                        EventInspectorQt PRIVATE $ {
                                          QT
                                        } ::Widgets $ { QT } ::Network)

#Helpful warning flags
                                        if (MSVC) target_compile_options(
                                            EventInspectorQt PRIVATE /
                                            W4) else()
                                            target_compile_options(
                                                EventInspectorQt PRIVATE -
                                                Wall - Wextra - Wpedantic)
                                                endif()
