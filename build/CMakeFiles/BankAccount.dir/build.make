# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.31

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/mercurykane/ClionProjects/BankAccount

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/mercurykane/ClionProjects/BankAccount/build

# Include any dependencies generated for this target.
include CMakeFiles/BankAccount.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/BankAccount.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/BankAccount.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/BankAccount.dir/flags.make

CMakeFiles/BankAccount.dir/codegen:
.PHONY : CMakeFiles/BankAccount.dir/codegen

CMakeFiles/BankAccount.dir/main.cpp.o: CMakeFiles/BankAccount.dir/flags.make
CMakeFiles/BankAccount.dir/main.cpp.o: /Users/mercurykane/ClionProjects/BankAccount/main.cpp
CMakeFiles/BankAccount.dir/main.cpp.o: CMakeFiles/BankAccount.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/mercurykane/ClionProjects/BankAccount/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/BankAccount.dir/main.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/BankAccount.dir/main.cpp.o -MF CMakeFiles/BankAccount.dir/main.cpp.o.d -o CMakeFiles/BankAccount.dir/main.cpp.o -c /Users/mercurykane/ClionProjects/BankAccount/main.cpp

CMakeFiles/BankAccount.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/BankAccount.dir/main.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/mercurykane/ClionProjects/BankAccount/main.cpp > CMakeFiles/BankAccount.dir/main.cpp.i

CMakeFiles/BankAccount.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/BankAccount.dir/main.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/mercurykane/ClionProjects/BankAccount/main.cpp -o CMakeFiles/BankAccount.dir/main.cpp.s

# Object files for target BankAccount
BankAccount_OBJECTS = \
"CMakeFiles/BankAccount.dir/main.cpp.o"

# External object files for target BankAccount
BankAccount_EXTERNAL_OBJECTS =

BankAccount: CMakeFiles/BankAccount.dir/main.cpp.o
BankAccount: CMakeFiles/BankAccount.dir/build.make
BankAccount: CMakeFiles/BankAccount.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/mercurykane/ClionProjects/BankAccount/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable BankAccount"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/BankAccount.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/BankAccount.dir/build: BankAccount
.PHONY : CMakeFiles/BankAccount.dir/build

CMakeFiles/BankAccount.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/BankAccount.dir/cmake_clean.cmake
.PHONY : CMakeFiles/BankAccount.dir/clean

CMakeFiles/BankAccount.dir/depend:
	cd /Users/mercurykane/ClionProjects/BankAccount/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/mercurykane/ClionProjects/BankAccount /Users/mercurykane/ClionProjects/BankAccount /Users/mercurykane/ClionProjects/BankAccount/build /Users/mercurykane/ClionProjects/BankAccount/build /Users/mercurykane/ClionProjects/BankAccount/build/CMakeFiles/BankAccount.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/BankAccount.dir/depend

