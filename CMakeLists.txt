cmake_minimum_required(VERSION 3.2)
project(cdoc VERSION 0.0.1)
find_package(Doxygen)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)
include(GenerateExportHeader)
include(GNUInstallDirs)
include_directories(${LIBXML2_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${CMAKE_BINARY_DIR})
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(PUBLIC_HEADER Token.h CDOCReader.h CDOCWriter.h CDOCExport.h)
if(WIN32)
	add_definitions(-DUNICODE -DWIN32_LEAN_AND_MEAN)
	list(APPEND LIBS Crypt32 NCrypt cryptui)
endif()
add_library(cdoc SHARED Writer.cpp CDOCWriter.cpp CDOCReader.cpp Crypto.cpp Token.cpp ${PUBLIC_HEADER})
set_target_properties(cdoc PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 0
	PUBLIC_HEADER "${PUBLIC_HEADER}"
	FRAMEWORK_VERSION 0
	FRAMEWORK YES
	MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.cdoc"
	MACOSX_RPATH YES
	MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
	MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
	C_VISIBILITY_PRESET hidden
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)
generate_export_header(cdoc EXPORT_FILE_NAME CDOCExport.h)
target_link_libraries(cdoc ${LIBXML2_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} ${LIBS})
add_executable(cdoc-tool main.cpp)
target_link_libraries(cdoc-tool cdoc)
if(DOXYGEN_FOUND)
	configure_file( ${CMAKE_SOURCE_DIR}/Doxyfile.in Doxyfile @ONLY )
	add_custom_target(docs ALL
		${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Generating API documentation with Doxygen" VERBATIM
	)
	if(APPLE)
		install(DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION $<TARGET_FILE_DIR:cdoc>/Resources/)
	else()
		install(DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR})
	endif()
endif()
