include_directories(
    .
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}
)

set( LIBSOURCES
    ${PROJECT_SOURCE_DIR}/src/secpolicy.c
    ${PROJECT_SOURCE_DIR}/src/proc.c
    ${PROJECT_SOURCE_DIR}/src/user.c
    ${PROJECT_SOURCE_DIR}/src/peer.c
    ${PROJECT_SOURCE_DIR}/src/strlcpy.c
    ${PROJECT_SOURCE_DIR}/src/challenge.c
    ${PROJECT_SOURCE_DIR}/src/comms.c
)

set( CMAKE_C_FLAGS "-ggdb -Wall" )
add_definitions( -D_GNU_SOURCE )

if( ENABLE_SHARED )
    add_library( libsecpolicy_shared SHARED ${LIBSOURCES} )
    set_target_properties( libsecpolicy_shared PROPERTIES
      COMPILE_FLAGS  "-fPIC -O0"
      VERSION "${PACKAGE_MINOR}.${PACKAGE_PATCH}"
      SOVERSION "${PACKAGE_MAJOR}"
      OUTPUT_NAME secpolicy
    )
    target_link_libraries( libsecpolicy_shared )
endif( ENABLE_SHARED )

if( ENABLE_STATIC )
    add_library( libsecpolicy_static STATIC ${LIBSOURCES} )
    set_target_properties( libsecpolicy_static PROPERTIES
      COMPILE_FLAGS  "-fPIC -O0"
      VERSION "${PACKAGE_MINOR}.${PACKAGE_PATCH}"
      SOVERSION "${PACKAGE_MAJOR}"
      OUTPUT_NAME secpolicy
    )
    target_link_libraries( libsecpolicy_static )
endif( ENABLE_STATIC )
