# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/vinny/projects/lmd

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/vinny/projects/lmd

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/vinny/projects/lmd/CMakeFiles /home/vinny/projects/lmd/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/vinny/projects/lmd/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named lmd

# Build rule for target.
lmd: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 lmd
.PHONY : lmd

# fast build rule for target.
lmd/fast:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/build
.PHONY : lmd/fast

src/cor_array.o: src/cor_array.c.o

.PHONY : src/cor_array.o

# target to build an object file
src/cor_array.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_array.c.o
.PHONY : src/cor_array.c.o

src/cor_array.i: src/cor_array.c.i

.PHONY : src/cor_array.i

# target to preprocess a source file
src/cor_array.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_array.c.i
.PHONY : src/cor_array.c.i

src/cor_array.s: src/cor_array.c.s

.PHONY : src/cor_array.s

# target to generate assembly for a file
src/cor_array.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_array.c.s
.PHONY : src/cor_array.c.s

src/cor_buf.o: src/cor_buf.c.o

.PHONY : src/cor_buf.o

# target to build an object file
src/cor_buf.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_buf.c.o
.PHONY : src/cor_buf.c.o

src/cor_buf.i: src/cor_buf.c.i

.PHONY : src/cor_buf.i

# target to preprocess a source file
src/cor_buf.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_buf.c.i
.PHONY : src/cor_buf.c.i

src/cor_buf.s: src/cor_buf.c.s

.PHONY : src/cor_buf.s

# target to generate assembly for a file
src/cor_buf.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_buf.c.s
.PHONY : src/cor_buf.c.s

src/cor_http.o: src/cor_http.c.o

.PHONY : src/cor_http.o

# target to build an object file
src/cor_http.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_http.c.o
.PHONY : src/cor_http.c.o

src/cor_http.i: src/cor_http.c.i

.PHONY : src/cor_http.i

# target to preprocess a source file
src/cor_http.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_http.c.i
.PHONY : src/cor_http.c.i

src/cor_http.s: src/cor_http.c.s

.PHONY : src/cor_http.s

# target to generate assembly for a file
src/cor_http.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_http.c.s
.PHONY : src/cor_http.c.s

src/cor_list.o: src/cor_list.c.o

.PHONY : src/cor_list.o

# target to build an object file
src/cor_list.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_list.c.o
.PHONY : src/cor_list.c.o

src/cor_list.i: src/cor_list.c.i

.PHONY : src/cor_list.i

# target to preprocess a source file
src/cor_list.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_list.c.i
.PHONY : src/cor_list.c.i

src/cor_list.s: src/cor_list.c.s

.PHONY : src/cor_list.s

# target to generate assembly for a file
src/cor_list.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_list.c.s
.PHONY : src/cor_list.c.s

src/cor_log.o: src/cor_log.c.o

.PHONY : src/cor_log.o

# target to build an object file
src/cor_log.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_log.c.o
.PHONY : src/cor_log.c.o

src/cor_log.i: src/cor_log.c.i

.PHONY : src/cor_log.i

# target to preprocess a source file
src/cor_log.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_log.c.i
.PHONY : src/cor_log.c.i

src/cor_log.s: src/cor_log.c.s

.PHONY : src/cor_log.s

# target to generate assembly for a file
src/cor_log.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_log.c.s
.PHONY : src/cor_log.c.s

src/cor_pool.o: src/cor_pool.c.o

.PHONY : src/cor_pool.o

# target to build an object file
src/cor_pool.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_pool.c.o
.PHONY : src/cor_pool.c.o

src/cor_pool.i: src/cor_pool.c.i

.PHONY : src/cor_pool.i

# target to preprocess a source file
src/cor_pool.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_pool.c.i
.PHONY : src/cor_pool.c.i

src/cor_pool.s: src/cor_pool.c.s

.PHONY : src/cor_pool.s

# target to generate assembly for a file
src/cor_pool.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_pool.c.s
.PHONY : src/cor_pool.c.s

src/cor_str.o: src/cor_str.c.o

.PHONY : src/cor_str.o

# target to build an object file
src/cor_str.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_str.c.o
.PHONY : src/cor_str.c.o

src/cor_str.i: src/cor_str.c.i

.PHONY : src/cor_str.i

# target to preprocess a source file
src/cor_str.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_str.c.i
.PHONY : src/cor_str.c.i

src/cor_str.s: src/cor_str.c.s

.PHONY : src/cor_str.s

# target to generate assembly for a file
src/cor_str.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/cor_str.c.s
.PHONY : src/cor_str.c.s

src/lmd.o: src/lmd.c.o

.PHONY : src/lmd.o

# target to build an object file
src/lmd.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/lmd.c.o
.PHONY : src/lmd.c.o

src/lmd.i: src/lmd.c.i

.PHONY : src/lmd.i

# target to preprocess a source file
src/lmd.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/lmd.c.i
.PHONY : src/lmd.c.i

src/lmd.s: src/lmd.c.s

.PHONY : src/lmd.s

# target to generate assembly for a file
src/lmd.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/lmd.c.s
.PHONY : src/lmd.c.s

src/lmd_db.o: src/lmd_db.c.o

.PHONY : src/lmd_db.o

# target to build an object file
src/lmd_db.c.o:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/lmd_db.c.o
.PHONY : src/lmd_db.c.o

src/lmd_db.i: src/lmd_db.c.i

.PHONY : src/lmd_db.i

# target to preprocess a source file
src/lmd_db.c.i:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/lmd_db.c.i
.PHONY : src/lmd_db.c.i

src/lmd_db.s: src/lmd_db.c.s

.PHONY : src/lmd_db.s

# target to generate assembly for a file
src/lmd_db.c.s:
	$(MAKE) -f CMakeFiles/lmd.dir/build.make CMakeFiles/lmd.dir/src/lmd_db.c.s
.PHONY : src/lmd_db.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... lmd"
	@echo "... src/cor_array.o"
	@echo "... src/cor_array.i"
	@echo "... src/cor_array.s"
	@echo "... src/cor_buf.o"
	@echo "... src/cor_buf.i"
	@echo "... src/cor_buf.s"
	@echo "... src/cor_http.o"
	@echo "... src/cor_http.i"
	@echo "... src/cor_http.s"
	@echo "... src/cor_list.o"
	@echo "... src/cor_list.i"
	@echo "... src/cor_list.s"
	@echo "... src/cor_log.o"
	@echo "... src/cor_log.i"
	@echo "... src/cor_log.s"
	@echo "... src/cor_pool.o"
	@echo "... src/cor_pool.i"
	@echo "... src/cor_pool.s"
	@echo "... src/cor_str.o"
	@echo "... src/cor_str.i"
	@echo "... src/cor_str.s"
	@echo "... src/lmd.o"
	@echo "... src/lmd.i"
	@echo "... src/lmd.s"
	@echo "... src/lmd_db.o"
	@echo "... src/lmd_db.i"
	@echo "... src/lmd_db.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

