cmake_minimum_required(VERSION 3.16)
project(cdoc VERSION 0.0.1)
find_package(Doxygen)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SWIG)
include(GenerateExportHeader)
include(GNUInstallDirs)

set(SIGNCERT "" CACHE STRING "Common name of certificate to used sign binaries, empty skip signing" )
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(INSTALL_FRAMEWORKDIR /Library/Frameworks CACHE STRING "Framework install target")
set(BUILD_SHARED_LIBS YES CACHE BOOL "Build library as SHARED or STATIC")
set(PUBLIC_HEADER Token.h CDOCReader.h CDOCWriter.h ${CMAKE_BINARY_DIR}/CDOCExport.h)
include_directories(${LIBXML2_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR})
if(WIN32)
	add_definitions(-DUNICODE -DWIN32_LEAN_AND_MEAN)
	list(APPEND LIBS Crypt32 NCrypt cryptui)
endif()

if(DOXYGEN_FOUND)
	configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in Doxyfile @ONLY)
	add_custom_target(docs ALL
		${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Generating API documentation with Doxygen" VERBATIM
	)
endif()

add_library(cdoc_private STATIC
	Crypto.cpp
	DDOCReader.cpp
	DDOCWriter.cpp
	XMLReader.cpp
	XMLWriter.cpp
)
set_property(TARGET cdoc_private PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(cdoc
	CDOCReader.cpp
	CDOCWriter.cpp
	Token.cpp
	${PUBLIC_HEADER}
	${RESOURCE_FILES}
)
set_target_properties(cdoc PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 0
	FRAMEWORK_VERSION 0
	FRAMEWORK YES
	PUBLIC_HEADER "${PUBLIC_HEADER}"
	RESOURCE "${RESOURCE_FILES}"
	MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.cdoc"
	MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
	MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
	C_VISIBILITY_PRESET hidden
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)
generate_export_header(cdoc EXPORT_FILE_NAME CDOCExport.h)
target_link_libraries(cdoc cdoc_private ${LIBXML2_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} ${LIBS})
install(TARGETS cdoc
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	RESOURCE DESTINATION ${CMAKE_INSTALL_DOCDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc
	FRAMEWORK DESTINATION ${INSTALL_FRAMEWORKDIR}
)

add_executable(cdoc-tool main.cpp)
target_link_libraries(cdoc-tool cdoc)
if(NOT APPLE)
	install(TARGETS cdoc-tool RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()

if(SWIG_FOUND AND WIN32)
	include(${SWIG_USE_FILE})
	set(CMAKE_SWIG_FLAGS -dllimport cdoc_csharp -namespace cdoc)
	set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
	set_property(SOURCE cdoc.i PROPERTY CPLUSPLUS ON)
	swig_add_library(cdoc_csharp TYPE SHARED LANGUAGE csharp SOURCES cdoc.i)
	swig_link_libraries(cdoc_csharp cdoc)
	set_target_properties(cdoc_csharp PROPERTIES DEBUG_OUTPUT_NAME "cdoc_csharpd")
	install(TARGETS cdoc_csharp DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(FILES $<TARGET_PDB_FILE:cdoc_csharp> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc_csharp FILES_MATCHING PATTERN "*.cs")
endif()

if(APPLE)
	add_custom_command(TARGET cdoc POST_BUILD
		COMMAND /usr/libexec/PlistBuddy -c "Add :MinimumOSVersion string ${CMAKE_OSX_DEPLOYMENT_TARGET}" $<TARGET_FILE_DIR:cdoc>/Info.plist
	)
	#add_custom_command(TARGET cdoc-tool POST_BUILD
	#	COMMAND mkdir -p $<TARGET_FILE_DIR:cdoc>/Resources
	#	COMMAND cp -a $<TARGET_FILE:cdoc-tool> $<TARGET_FILE_DIR:cdoc>/Resources/
	#)
	if(DOXYGEN_FOUND)
		add_custom_command(TARGET docs POST_BUILD
			COMMAND mkdir -p $<TARGET_FILE_DIR:cdoc>/Resources
			COMMAND cp -a ${CMAKE_BINARY_DIR}/doc/* $<TARGET_FILE_DIR:cdoc>/Resources/
		)
	endif()
	set_target_properties(cdoc-tool PROPERTIES
		BUILD_WITH_INSTALL_RPATH YES
		INSTALL_RPATH "@executable_path/../../../..;@executable_path"
	)
	add_custom_target(codesign DEPENDS cdoc
		COMMAND codesign -f -s "Developer ID Application: ${SIGNCERT}"
			$<TARGET_FILE_DIR:cdoc>/Resources/cdoc-tool
			$<TARGET_FILE_DIR:cdoc>/../..
	)
	add_custom_target(pkg DEPENDS cdoc-tool
		COMMAND make install DESTDIR=install
		COMMAND pkgbuild --root install "$<$<BOOL:${SIGNCERT}>:--sign;${SIGNCERT}>"
			${CMAKE_BINARY_DIR}/cdoc_${PROJECT_VERSION}$ENV{VER_SUFFIX}.pkg
		COMMAND_EXPAND_LISTS
	)
	add_custom_target(debugpkg DEPENDS cdoc-tool
		COMMAND dsymutil -o cdoc.dSYM $<TARGET_FILE:cdoc> $<TARGET_FILE:cdoc-tool>
		COMMAND zip -r ${CMAKE_BINARY_DIR}/cdoc-dbg_${PROJECT_VERSION}$ENV{VER_SUFFIX}.zip cdoc.dSYM
	)
elseif(WIN32)
	set_target_properties(cdoc PROPERTIES DEBUG_OUTPUT_NAME "cdocd")
	install(FILES $<TARGET_PDB_FILE:cdoc> $<TARGET_PDB_FILE:cdoc-tool> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
else()
	add_custom_target(debs
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		COMMAND dh_make --createorig --addmissing --defaultless -y -p ${PROJECT_NAME}_${PROJECT_VERSION}
		COMMAND dch --distribution unstable -v ${PROJECT_VERSION} 'Release: ${PROJECT_VERSION}.'
		COMMAND dpkg-buildpackage -rfakeroot -us -uc
	)
endif()
