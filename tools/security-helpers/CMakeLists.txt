#
# This file is distributed under the MIT License. See LICENSE.md for details.
#
set(SECURITY_HELPERS "lifting.sh" "strip-objdump-plt.sh" "analize.sh")

foreach(SECURITY_HELPER ${SECURITY_HELPERS})
	add_custom_command(OUTPUT ${SECURITY_HELPER} 
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/${SECURITY_HELPER}" "${CMAKE_BINARY_DIR}/bin/")
endforeach(SECURITY_HELPER)

add_custom_target(security-helpers ALL 
	COMMAND echo "Building security helpers scripts"
	DEPENDS ${SECURITY_HELPERS})
