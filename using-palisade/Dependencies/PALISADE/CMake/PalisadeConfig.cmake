# - Config file for the Palisade package
# It defines the following variables
#  PALISADE_INCLUDE_DIRS - include directories for Palisade
#  PALISADE_LIBRARIES    - libraries to link against

get_filename_component(PALISADE_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if(NOT Palisade_BINARY_DIR)
  include("${PALISADE_CMAKE_DIR}/PalisadeTargets.cmake")
endif()

# These are IMPORTED targets created by PalisadeTargets.cmake
set(PALISADE_INCLUDE "C:/Program Files (x86)/PALISADE/include/palisade")
set(PALISADE_LIBDIR "C:/Program Files (x86)/PALISADE/lib")
set(PALISADE_LIBRARIES PALISADEcore PALISADEpke PALISADEtrapdoor PALISADEabe PALISADEsignature PALISADEbinfhe  -fopenmp)

set(OPENMP_INCLUDES "" )
set(OPENMP_LIBRARIES "" )

set(PALISADE_CXX_FLAGS " -Wall -Werror -O3  -DPALISADE_VERSION=1.10.0 -Wno-parentheses -fopenmp -fopenmp")
set(PALISADE_C_FLAGS " -Wall -Werror -O3  -DPALISADE_VERSION=1.10.0 -fopenmp -fopenmp")

if( "OFF" STREQUAL "Y" )
	set(PALISADE_CXX_FLAGS "${PALISADE_CXX_FLAGS} -DWITH_NTL" )
	set(PALISADE_C_FLAGS "${PALISADE_C_FLAGS} -DWITH_NTL")
endif()

set (PALISADE_EXE_LINKER_FLAGS "  ")
