# - Try to find libosmoasn1rrc
# Once done this will define
#  LIBOSMO_ASN1_RRC_FOUND - System has libosmoasn1rrc
#  LIBOSMO_ASN1_RRC_INCLUDE_DIRS - The libosmoasn1rrc include directories
#  LIBOSMO_ASN1_RRC_LIBRARIES - The libraries needed to use libosmoasn1rrc
#  LIBOSMO_ASN1_RRC_DEFINITIONS - Compiler switches required for using libosmoasn1rrc

find_package(PkgConfig)
pkg_check_modules(PC_lib_osmo_asn1_rrc QUIET libosmo-asn1-rrc)
set(LIBOSMO_ASN1_RRC_DEFINITIONS ${PC_LIBOSMO_ASN1_RRC_CFLAGS_OTHER})
message(STATUS "found? ${PKG_CONFIG_FOUND} ")
message(STATUS "include? ${PC_lib_osmo_asn1_rrc_INCLUDEDIR} ")
message(STATUS "include? ${PC_lib_osmo_asn1_rrc_INCLUDE_DIRS} ")

find_path(LIBOSMO_ASN1_RRC_INCLUDE_DIR osmocom/rrc/UL-DCCH-Message.h
          HINTS ${PC_lib_osmo_asn1_rrc_INCLUDEDIR} ${PC_lib_osmo_asn1_rrc_INCLUDE_DIRS}
          PATH_SUFFIXES lib_osmo_asn1_rrc )

find_library(LIBOSMO_ASN1_RRC_LIBRARY NAMES osmo-asn1-rrc libosmo-asn1-rrc
         HINTS ${PC_lib_osmo_asn1_rrc_LIBDIR} ${PC_lib_osmo_asn1_rrc_LIBRARY_DIRS} )

set(LIBOSMO_ASN1_RRC_LIBRARIES ${LIBOSMO_ASN1_RRC_LIBRARY} )
set(LIBOSMO_ASN1_RRC_INCLUDE_DIRS ${LIBOSMO_ASN1_RRC_INCLUDE_DIR} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBOSMO_ASN1_RRC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(libosmoasn1rrc  DEFAULT_MSG
                                  LIBOSMO_ASN1_RRC_LIBRARY LIBOSMO_ASN1_RRC_INCLUDE_DIR)

mark_as_advanced(LIBOSMO_ASN1_RRC_INCLUDE_DIR LIBOSMO_ASN1_RRC_LIBRARY )