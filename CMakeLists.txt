cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)

set(CPACK_PACKAGE_NAME "metagsm")
set(CPACK_PACKAGE_VENDOR "Security Research Labs")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "GSM/3G/LTE parser")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")

# -----------------------------------------------------------------------------
# Make RelWithDebInfo the default build type if otherwise not set
# -----------------------------------------------------------------------------
set(build_types Debug Release RelWithDebInfo MinSizeRel)
if(NOT CMAKE_BUILD_TYPE)
	message(STATUS "You can choose the type of build, options are:${build_types}")
	set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE String
		"Options are ${build_types}"
		FORCE
	)

	# Provide drop down menu options in cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${build_types})
endif()
message(STATUS "Doing a ${CMAKE_BUILD_TYPE} build")

# -----------------------------------------------------------------------------
# Option to enable/disable assertions
# -----------------------------------------------------------------------------

# Filter out definition of NDEBUG from the default build configuration flags.
# We will add this ourselves if we want to disable assertions
foreach (build_config ${build_types})
	string(TOUPPER ${build_config} upper_case_build_config)
	foreach (language CXX C)
		set(VAR_TO_MODIFY "CMAKE_${language}_FLAGS_${upper_case_build_config}")
		string(REGEX REPLACE "(^| )[/-]D *NDEBUG($| )"
							 " "
							 replacement
							 "${${VAR_TO_MODIFY}}"
			  )
		#message("Original (${VAR_TO_MODIFY}) is ${${VAR_TO_MODIFY}} replacement is ${replacement}")
		set(${VAR_TO_MODIFY} "${replacement}" CACHE STRING "Default flags for ${build_config} configuration" FORCE)
	endforeach()
endforeach()

project (glueminisat)

option(ENABLE_ASSERTIONS "Build with assertions enabled" ON)
if (ENABLE_ASSERTIONS)
	# NDEBUG was already removed.
else()
	# Note this definition doesn't appear in the cache variables.
	add_definitions(-DNDEBUG)
endif()

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake) #m4-extra contains some library search cmake stuff

macro(add_c_flag flagname)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flagname}")
endmacro()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
SET(CMAKE_C_FLAGS_RELWITHDEBINFO "-ggdb -O3")
SET(CMAKE_C_FLAGS_RELEASE "-O3 -g0 -DNDEBUG")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")

include(CheckCCompilerFlag)
macro(add_c_flag_if_supported flagname)
	check_c_compiler_flag("${flagname}" HAVE_FLAG_${flagname})
	if(HAVE_FLAG_${flagname})
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flagname}")
		message(STATUS "flag ${flagname} supported")
	else()
		message(STATUS "flag ${flagname} NOT supported")
	endif()
endmacro()

add_c_flag_if_supported("-Wall")
add_c_flag_if_supported("-Wextra")
add_c_flag_if_supported("-Wunused")
add_c_flag_if_supported("-pedantic")
add_c_flag_if_supported("-Wsign-compare")
add_c_flag_if_supported("-fno-omit-frame-pointer")
add_c_flag_if_supported("-Wtype-limits")
add_c_flag_if_supported("-Wuninitialized")
add_c_flag_if_supported("-Wno-deprecated")
add_c_flag_if_supported("-Wstrict-aliasing")
add_c_flag_if_supported("-Wpointer-arith")
add_c_flag_if_supported("-Wheader-guard")

find_package(MySQL)
IF (MYSQL_FOUND)
	MESSAGE(STATUS "OK, Found MySQL!")
	include_directories(${MYSQL_INCLUDE_DIR}/mysql)
	link_directories(${MYSQL_LIB_DIR})
	add_definitions( -DUSE_MYSQL )
else ()
	MESSAGE(STATUS "WARNING: Did not find MySQL, MySQL support will be disabled")
endif()

find_package(Sqlite3)
IF (SQLITE3_FOUND)
	MESSAGE(STATUS "OK, Found Sqlite3!")
	include_directories(${SQLITE3_INCLUDE_DIR})
	add_definitions( -DUSE_SQLITE )
else ()
	MESSAGE(STATUS "WARNING: Did not find Sqlite3, Sqlite3 support will be disabled")
endif ()

find_package(libasn1c REQUIRED)
include_directories(${LIBASN1C_INCLUDE_DIRS})

find_package(libosmoasn1rrc REQUIRED)
include_directories(${LIBOSMO_ASN1_RRC_INCLUDE_DIR})

find_package(libosmocore REQUIRED)
include_directories(${LIBOSMOCORE_INCLUDE_DIR})

find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDE_DIR})

macro(metagsm_add_public_header LIBTARGET HEADER)
	set(HEADER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER}")
	if(EXISTS "${HEADER_PATH}")
		# Get existing PUBLIC_HEADER
		get_target_property(EXISTING_PUBLIC_HEADERS ${LIBTARGET} PUBLIC_HEADER)
		if(EXISTING_PUBLIC_HEADERS)
			list(APPEND EXISTING_PUBLIC_HEADERS "${HEADER_PATH}")
		else()
			# Do not append to empty list
			set(EXISTING_PUBLIC_HEADERS "${HEADER_PATH}")
		endif()
		set_target_properties(${LIBTARGET}
							  PROPERTIES
							  PUBLIC_HEADER "${EXISTING_PUBLIC_HEADERS}"
							 )
	else()
		message(FATAL_ERROR "Cannot add public header, file ${HEADER_PATH} does not exist.")
	endif()
endmacro()

# -----------------------------------------------------------------------------
# Provide an export name to be used by targets that wish to export themselves.
# -----------------------------------------------------------------------------
set(METAGSM_EXPORT_NAME "MetaGSMTargets")


set(metagsm_lib_files
	address.c assignment.c bit_func.c ccch.c cch.c chan_detect.c crc.c
	umts_rrc.c diag_input.c gprs.c gsm_interleave.c cell_info.c
	l3_handler.c output.c process.c punct.c rand_check.c rlcmac.c
	sch.c session.c sms.c tch.c viterbi.c
)

set(my_link_libs "")

IF (MYSQL_FOUND)
	set(metagsm_lib_files ${metagsm_lib_files} mysql_api.c)
	SET(my_link_libs ${my_link_libs} ${MYSQL_LIB})
	message(STATUS "heee mysql")
ENDIF()

IF (SQLITE3_FOUND)
	set(metagsm_lib_files ${metagsm_lib_files} sqlite_api.c)
	SET(my_link_libs ${my_link_libs} ${SQLITE3_LIBRARIES})
	message(STATUS "heee sqlite")
ENDIF()

add_library(libmetagsm SHARED ${metagsm_lib_files})

target_link_libraries(libmetagsm
	${my_link_libs}
	${LIBASN1C_LIBRARIES}
	${LIBOSMO_ASN1_RRC_LIBRARY}
	${LIBOSMOCORE_LIBRARIES}
	${PCAP_LIBRARY}
)

set_target_properties(libmetagsm PROPERTIES
	OUTPUT_NAME metagsm
	PUBLIC_HEADER "${metagsm_public_headers}"
)

metagsm_add_public_header(libmetagsm
	address.h ccch.h crc.h gsm_interleave.h process.h
	sch.h  umts_rrc.h assignment.h
	cch.h diag_input.h l3_handler.h punct.h
	session.h viterbi.h bit_func.h cell_info.h
	diag_structs.h mysql_api.h rand_check.h
	sms.h burst_desc.h rlcmac.h
	chan_detect.h gprs.h output.h
	sqlite_api.h
)

set(HEADER_DEST "${CMAKE_BINARY_DIR}/include/metagsm")
add_custom_target(CopyPublicHeaders ALL)
get_target_property(metagsm_public_headers libmetagsm PUBLIC_HEADER)
foreach(public_header ${metagsm_public_headers})
	get_filename_component(HEADER_NAME ${public_header} NAME)
	add_custom_command(TARGET CopyPublicHeaders PRE_BUILD
					   COMMAND ${CMAKE_COMMAND} -E make_directory
							   "${HEADER_DEST}"
					   COMMAND ${CMAKE_COMMAND} -E echo
					   "Copying ${HEADER_NAME} to ${HEADER_DEST}"
					   COMMAND ${CMAKE_COMMAND} -E
						   copy_if_different
						   ${public_header}
						   "${HEADER_DEST}"
					  )
endforeach()

install(TARGETS libmetagsm
	EXPORT ${METAGSM_EXPORT_NAME}
	LIBRARY DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
	PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/metagsm"
)

set(CPACK_PACKAGE_EXECUTABLES "")

############

add_executable (diag_import
	diag_import.c
)

set_target_properties(diag_import PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(diag_import PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
target_link_libraries(diag_import
	libmetagsm
)

install(TARGETS diag_import
	EXPORT ${METAGSM_EXPORT_NAME}
	RUNTIME DESTINATION bin
)
SET(CPACK_PACKAGE_EXECUTABLES ${CPACK_PACKAGE_EXECUTABLES} "diag_import")

############

add_executable (hex_import
	hex_import.c
)

set_target_properties(hex_import PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(hex_import PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
target_link_libraries(hex_import
	libmetagsm
)

install(TARGETS hex_import
	EXPORT ${METAGSM_EXPORT_NAME}
	RUNTIME DESTINATION bin
)
SET(CPACK_PACKAGE_EXECUTABLES ${CPACK_PACKAGE_EXECUTABLES} "hex_import")

############

add_executable (gsmtap_import
	gsmtap_import.c
)

set_target_properties(gsmtap_import PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(gsmtap_import PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
target_link_libraries(gsmtap_import
	libmetagsm
)

install(TARGETS gsmtap_import
	EXPORT ${METAGSM_EXPORT_NAME}
	RUNTIME DESTINATION bin
)
SET(CPACK_PACKAGE_EXECUTABLES ${CPACK_PACKAGE_EXECUTABLES} "gsmtap_import")

############

if (MYSQL_FOUND)
	add_executable (db_import
		db_import.c
	)

	set_target_properties(db_import PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
	set_target_properties(db_import PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
	target_link_libraries(db_import
		libmetagsm
	)

	install(TARGETS db_import
		EXPORT ${METAGSM_EXPORT_NAME}
		RUNTIME DESTINATION bin
	)
	SET(CPACK_PACKAGE_EXECUTABLES ${CPACK_PACKAGE_EXECUTABLES} "db_import")
endif()

