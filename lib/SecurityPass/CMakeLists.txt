revng_add_analyses_library(revngSecurityPass
	CommonDefinitions.cpp
	MaxStepsPass.cpp           		
	BackwardPropagationPass.cpp
	LoopDependenciesPass.cpp
	RevngFunctionParamsPass.cpp
	SecurityWrapperPass.cpp
	FunctionParamsUsagePass.cpp)

target_link_libraries(revngSecurityPass	
	revngSupport)
			





# SET(COMPILE_FLAGS " -g -fno-rtti")
# 
# SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${COMPILE_FLAGS}" )
# 
# add_llvm_library(RevngSecurityPass MODULE
#   CommonDefinitions.cpp
#   MaxStepsPass.cpp
#   BackwardPropagationPass.cpp
#   LoopDependenciesPass.cpp
#   RevngFunctionParamsPass.cpp
#   SecurityWrapperPass.cpp
#   FunctionParamsUsagePass.cpp
#   )



# set(REVNG_SECURITY_PLUGINS
#   MaxStepsPass
#   BackwardPropagationPass
#   RevngFunctionParamsPass
#   FunctionParamsUsagePass
#   LoopDependenciesPass
#   SecurityWrapperPass
#   )

# set(MaxStepsPass_SOURCES
#   MaxStepsPass.cpp)
# set(BackwardPropagationPass_SOURCES
#   BackwardPropagationPass.cpp)
# set(LoopDependenciesPass_SOURCES
#   LoopDependenciesPass.cpp)
# set(RevngFunctionParamsPass_SOURCES
#   RevngFunctionParamsPass.cpp)
# set(FunctionParamsUsagePass_SOURCES
#   FunctionParamsUsagePass.cpp)
# set(SecurityWrapperPass_SOURCES
#   SecurityWrapperPass.cpp)


# # CONFIGURE THE PLUGIN LIBRARIES
# # ==============================
# foreach( plugin ${REVNG_SECURITY_PLUGINS} )
#   # Create a library corresponding to 'plugin'


#   add_library(
#     ${plugin}
#     SHARED
#     ${${plugin}_SOURCES}
#   )


#   add_library(
#     LLVM${plugin}
#     MODULE
#     ${${plugin}_SOURCES}
#   )


#   # Configure include directories for 'plugin'
#   target_include_directories(
#     ${plugin}
#     PUBLIC
#     "${CMAKE_CURRENT_SOURCE_DIR}/../include"
#     )

#   target_include_directories(
#     LLVM${plugin}
#     PUBLIC
#     "${CMAKE_CURRENT_SOURCE_DIR}/../include"
#     )
# endforeach()
