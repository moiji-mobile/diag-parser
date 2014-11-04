# - Try to find libasn1c
# Once done this will define
#  LIBASN1C_FOUND - System has libasn1c
#  LIBASN1C_INCLUDE_DIRS - The libasn1c include directories
#  LIBASN1C_LIBRARIES - The libraries needed to use libasn1c
#  LIBASN1C_DEFINITIONS - Compiler switches required for using libasn1c

find_package(PkgConfig)
pkg_check_modules(PC_libasn1c QUIET libasn1c)
set(LIBASN1C_DEFINITIONS ${PC_LIBASN1C_CFLAGS_OTHER})
message(STATUS "found? ${PKG_CONFIG_FOUND} ")

find_path(LIBASN1C_INCLUDE_DIR asn_application.h
          HINTS ${PC_libasn1c_INCLUDEDIR} ${PC_libasn1c_INCLUDE_DIRS}
          PATH_SUFFIXES libasn1c )

find_library(LIBASN1C_LIBRARY NAMES libasn1c asn1c
         HINTS ${PC_libasn1c_LIBDIR} ${PC_libasn1c_LIBRARY_DIRS} )

set(LIBASN1C_LIBRARIES ${LIBASN1C_LIBRARY} )
set(LIBASN1C_INCLUDE_DIRS ${LIBASN1C_INCLUDE_DIR} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBASN1C_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(libasn1c  DEFAULT_MSG
                                  LIBASN1C_LIBRARY LIBASN1C_INCLUDE_DIR)

mark_as_advanced(LIBASN1C_INCLUDE_DIR LIBASN1C_LIBRARY )