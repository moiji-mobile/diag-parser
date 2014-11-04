# - Try to find libosmocore
# Once done this will define
#  LIBOSMOCORE_FOUND - System has libosmocore
#  LIBOSMOCORE_INCLUDE_DIRS - The libosmocore include directories
#  LIBOSMOCORE_LIBRARIES - The libraries needed to use libosmocore
#  LIBOSMOCORE_DEFINITIONS - Compiler switches required for using libosmocore

find_package(PkgConfig)
pkg_check_modules(PC_libosmocore QUIET libosmocore)
set(LIBOSMOCORE_DEFINITIONS ${PC_LIBOSMOCORE_CFLAGS_OTHER})

find_path(LIBOSMOCORE_INCLUDE_DIR osmocom/core/application.h
          HINTS ${PC_libosmocore_INCLUDEDIR} ${PC_libosmocore_INCLUDE_DIRS}
          PATH_SUFFIXES libosmocore )

find_library(LIBOSMOCORE_LIBRARY NAMES libosmocore osmocore
         HINTS ${PC_libosmocore_LIBDIR} ${PC_libosmocore_LIBRARY_DIRS} )

find_library(LIBOSMOCORE_GSM_LIBRARY NAMES libosmogsm osmogsm
         HINTS ${PC_libosmocore_LIBDIR} ${PC_libosmocore_LIBRARY_DIRS} )

set(LIBOSMOCORE_LIBRARIES ${LIBOSMOCORE_LIBRARY} ${LIBOSMOCORE_GSM_LIBRARY})
set(LIBOSMOCORE_INCLUDE_DIRS ${LIBOSMOCORE_INCLUDE_DIR} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBOSMOCORE_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(libosmocore  DEFAULT_MSG
                                  LIBOSMOCORE_LIBRARY LIBOSMOCORE_INCLUDE_DIR)

mark_as_advanced(LIBOSMOCORE_INCLUDE_DIR LIBOSMOCORE_LIBRARY )