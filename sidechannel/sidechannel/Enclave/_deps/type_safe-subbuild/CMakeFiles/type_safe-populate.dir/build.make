# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

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
CMAKE_COMMAND = /opt/cmake/bin/cmake

# The command to remove a file.
RM = /opt/cmake/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild

# Utility rule file for type_safe-populate.

# Include any custom commands dependencies for this target.
include CMakeFiles/type_safe-populate.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/type_safe-populate.dir/progress.make

CMakeFiles/type_safe-populate: CMakeFiles/type_safe-populate-complete

CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-install
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-mkdir
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-download
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-patch
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-configure
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-build
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-install
CMakeFiles/type_safe-populate-complete: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-test
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Completed 'type_safe-populate'"
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles
	/opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles/type_safe-populate-complete
	/opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-done

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update:
.PHONY : type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-build: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-configure
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "No build step for 'type_safe-populate'"
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E echo_append
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-build

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-configure: type_safe-populate-prefix/tmp/type_safe-populate-cfgcmd.txt
type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-configure: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-patch
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "No configure step for 'type_safe-populate'"
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E echo_append
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-configure

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-download: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-gitinfo.txt
type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-download: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-mkdir
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Performing download step (git clone) for 'type_safe-populate'"
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps && /opt/cmake/bin/cmake -P /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/tmp/type_safe-populate-gitclone.cmake
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps && /opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-download

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-install: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-build
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "No install step for 'type_safe-populate'"
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E echo_append
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-install

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-mkdir:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Creating directories for 'type_safe-populate'"
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-src
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/tmp
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src
	/opt/cmake/bin/cmake -E make_directory /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp
	/opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-mkdir

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-patch: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "No patch step for 'type_safe-populate'"
	/opt/cmake/bin/cmake -E echo_append
	/opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-patch

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update:
.PHONY : type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-test: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-install
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "No test step for 'type_safe-populate'"
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E echo_append
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-build && /opt/cmake/bin/cmake -E touch /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-test

type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-download
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Performing update step for 'type_safe-populate'"
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-src && /opt/cmake/bin/cmake -P /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/type_safe-populate-prefix/tmp/type_safe-populate-gitupdate.cmake

type_safe-populate: CMakeFiles/type_safe-populate
type_safe-populate: CMakeFiles/type_safe-populate-complete
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-build
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-configure
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-download
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-install
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-mkdir
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-patch
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-test
type_safe-populate: type_safe-populate-prefix/src/type_safe-populate-stamp/type_safe-populate-update
type_safe-populate: CMakeFiles/type_safe-populate.dir/build.make
.PHONY : type_safe-populate

# Rule to build all files generated by this target.
CMakeFiles/type_safe-populate.dir/build: type_safe-populate
.PHONY : CMakeFiles/type_safe-populate.dir/build

CMakeFiles/type_safe-populate.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/type_safe-populate.dir/cmake_clean.cmake
.PHONY : CMakeFiles/type_safe-populate.dir/clean

CMakeFiles/type_safe-populate.dir/depend:
	cd /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild /home/rokwall/code/pktransfer/sidechannel/sidechannel/Enclave/_deps/type_safe-subbuild/CMakeFiles/type_safe-populate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/type_safe-populate.dir/depend

