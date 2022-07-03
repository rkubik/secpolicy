cmake_minimum_required( VERSION 3.0 )

project( secpolicy )

set( CMAKE_INSTALL_PREFIX "/" )

set( PACKAGE_MAJOR 0 )
set( PACKAGE_MINOR 1 )
set( PACKAGE_PATCH 0 )

option( ENABLE_STATIC "Enable static library." ON )
option( ENABLE_SHARED "Enable shared library." ON )
option( ENABLE_TESTS "Enable tests." ON )
option( ENABLE_EXAMPLES "Enable examples." ON )

message( "MAJOR: ${PACKAGE_MAJOR}" )
message( "MINOR: ${PACKAGE_MINOR}" )
message( "PATCH: ${PACKAGE_PATCH}" )

add_subdirectory( include )
add_subdirectory( lib )

if( ENABLE_EXAMPLES )
add_subdirectory( examples )
endif( ENABLE_EXAMPLES )

if( ENABLE_TESTS )
enable_testing()
add_subdirectory( test )
endif( ENABLE_TESTS )
