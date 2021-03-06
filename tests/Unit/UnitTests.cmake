#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

cmake_policy(SET CMP0060 NEW)

set(SRC "${CMAKE_SOURCE_DIR}/tests/Unit")

find_package(Boost REQUIRED COMPONENTS unit_test_framework)

#
# test_lazysmallbitvector
#

add_executable(test_lazysmallbitvector "${SRC}/LazySmallBitVector.cpp")
target_include_directories(test_lazysmallbitvector
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_lazysmallbitvector
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_lazysmallbitvector COMMAND test_lazysmallbitvector)
set_tests_properties(test_lazysmallbitvector PROPERTIES LABELS "unit")

#
# test_stackanalysis
#

add_executable(test_stackanalysis "${SRC}/StackAnalysis.cpp")
target_include_directories(test_stackanalysis
  PRIVATE "${CMAKE_SOURCE_DIR}"
          "${CMAKE_SOURCE_DIR}/lib/StackAnalysis"
          "${CMAKE_BINARY_DIR}/lib/StackAnalysis")
target_link_libraries(test_stackanalysis
  revngStackAnalysis
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_stackanalysis COMMAND test_stackanalysis)
set_tests_properties(test_stackanalysis PROPERTIES LABELS "unit")

#
# test_classsentinel
#

add_executable(test_classsentinel "${SRC}/ClassSentinel.cpp")
target_include_directories(test_classsentinel
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_classsentinel
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_classsentinel COMMAND test_classsentinel)
set_tests_properties(test_classsentinel PROPERTIES LABELS "unit")

#
# test_irhelpers
#

add_executable(test_irhelpers "${SRC}/IRHelpers.cpp")
target_include_directories(test_irhelpers
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_irhelpers
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_irhelpers COMMAND test_irhelpers)
set_tests_properties(test_irhelpers PROPERTIES LABELS "unit")

#
# test_irhelpers
#

add_executable(test_advancedvalueinfo "${SRC}/AdvancedValueInfo.cpp")
target_include_directories(test_advancedvalueinfo
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_advancedvalueinfo
  revngSupport
  revngBasicAnalyses
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_advancedvalueinfo COMMAND test_advancedvalueinfo)
set_tests_properties(test_advancedvalueinfo PROPERTIES LABELS "unit")

#
# test_zipmapiterator
#

add_executable(test_zipmapiterator "${SRC}/ZipMapIterator.cpp")
target_include_directories(test_zipmapiterator
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_zipmapiterator
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_zipmapiterator COMMAND test_zipmapiterator)
set_tests_properties(test_zipmapiterator PROPERTIES LABELS "unit")

#
# test_constantrangeset
#

add_executable(test_constantrangeset "${SRC}/ConstantRangeSet.cpp")
target_include_directories(test_constantrangeset
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_constantrangeset
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_constantrangeset COMMAND test_constantrangeset)
set_tests_properties(test_constantrangeset PROPERTIES LABELS "unit")

#
#
# test_shrinkinstructionoperands
#

add_executable(test_shrinkinstructionoperands "${SRC}/ShrinkInstructionOperandsPass.cpp")
target_include_directories(test_shrinkinstructionoperands
  PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(test_shrinkinstructionoperands
  revngSupport
  revngUnitTestHelpers
  Boost::unit_test_framework
  ${LLVM_LIBRARIES})
add_test(NAME test_shrinkinstructionoperands COMMAND test_shrinkinstructionoperands)
set_tests_properties(test_shrinkinstructionoperands PROPERTIES LABELS "unit")
