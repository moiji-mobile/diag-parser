# - Try to find Talloc
# Once done this will define
#
#  TALLOC_FOUND - system has Talloc
#  TALLOC_INCLUDE_DIRS - the Talloc include directory
#  TALLOC_LIBRARIES - Link these to use Talloc
#  TALLOC_DEFINITIONS - Compiler switches required for using Talloc
#
#  Copyright (c) 2010 Holger Hetterich <hhetter@novell.com>
#  Copyright (c) 2007 Andreas Schneider <mail@cynapses.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (TALLOC_LIBRARIES AND TALLOC_INCLUDE_DIRS)
  # in cache already
  set(TALLOC_FOUND TRUE)
else (TALLOC_LIBRARIES AND TALLOC_INCLUDE_DIRS)
  find_path(TALLOC_INCLUDE_DIR
    NAMES
      talloc.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

  find_library(TALLOC_LIBRARY
    NAMES
      talloc
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  if (TALLOC_LIBRARY)
    set(TALLOC_FOUND TRUE)
  endif (TALLOC_LIBRARY)

  set(TALLOC_INCLUDE_DIRS
    ${INIPARSER_INCLUDE_DIR}
  )

  if (TALLOC_FOUND)
    set(TALLOC_LIBRARIES
      ${TALLOC_LIBRARIES}
      ${TALLOC_LIBRARY}
    )
  endif (TALLOC_FOUND)

  if (TALLOC_INCLUDE_DIRS AND TALLOC_LIBRARIES)
     set(TALLOC_FOUND TRUE)
  endif (TALLOC_INCLUDE_DIRS AND TALLOC_LIBRARIES)

  if (TALLOC_FOUND)
    if (NOT Talloc_FIND_QUIETLY)
      message(STATUS "Found Talloc: ${TALLOC_LIBRARIES}")
    endif (NOT Talloc_FIND_QUIETLY)
  else (TALLOC_FOUND)
    if (Talloc_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find Talloc")
    endif (Talloc_FIND_REQUIRED)
  endif (TALLOC_FOUND)

  # show the INIPARSER_INCLUDE_DIRS and INIPARSER_LIBRARIES variables only in the advanced view
  mark_as_advanced(TALLOC_INCLUDE_DIRS TALLOC_LIBRARIES)

endif (TALLOC_LIBRARIES AND TALLOC_INCLUDE_DIRS)

