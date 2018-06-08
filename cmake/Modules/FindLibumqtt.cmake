# - Try to find libumqtt
# Once done this will define
#  LIBUMQTT_FOUND          - System has libumqtt
#  LIBUMQTT_INCLUDE_DIR    - The libumqtt include directories
#  LIBUMQTT_LIBRARY        - The libraries needed to use libumqtt

find_path(LIBUMQTT_INCLUDE_DIR umqtt)
find_library(LIBUMQTT_LIBRARY umqtt PATH_SUFFIXES lib64)

if(LIBUMQTT_INCLUDE_DIR)
  file(STRINGS "${LIBUMQTT_INCLUDE_DIR}/umqtt/config.h"
      LIBUMQTT_VERSION_MAJOR REGEX "^#define[ \t]+UMQTT_VERSION_MAJOR[ \t]+[0-9]+")
  file(STRINGS "${LIBUMQTT_INCLUDE_DIR}/umqtt/config.h"
      LIBUMQTT_VERSION_MINOR REGEX "^#define[ \t]+UMQTT_VERSION_MINOR[ \t]+[0-9]+")
  string(REGEX REPLACE "[^0-9]+" "" LIBUMQTT_VERSION_MAJOR "${LIBUMQTT_VERSION_MAJOR}")
  string(REGEX REPLACE "[^0-9]+" "" LIBUMQTT_VERSION_MINOR "${LIBUMQTT_VERSION_MINOR}")
  set(LIBUMQTT_VERSION "${LIBUMQTT_VERSION_MAJOR}.${LIBUMQTT_VERSION_MINOR}")
  unset(LIBUMQTT_VERSION_MINOR)
  unset(LIBUMQTT_VERSION_MAJOR)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBUMQTT_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(Libumqtt REQUIRED_VARS
                                  LIBUMQTT_LIBRARY LIBUMQTT_INCLUDE_DIR
                                  VERSION_VAR LIBUMQTT_VERSION)

mark_as_advanced(LIBUMQTT_INCLUDE_DIR LIBUMQTT_LIBRARY)
