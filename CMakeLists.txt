cmake_minimum_required(VERSION 3.5...4.0)

project(SNOW LANGUAGES C)

add_executable(snow
  loader.c)
target_link_options(snow PRIVATE
  -pthread)
