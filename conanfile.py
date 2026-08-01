from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
from conan.tools.files import copy, load
from conan.errors import ConanInvalidConfiguration
import os
import re

required_conan_version = ">=1.50.0"


class PlmConan(ConanFile):
    name = "plm"
    description = "single-file public domain libraries for C/C++"
    license = ("Unlicense", "MIT")
    homepage = "https://github.com/mr6r4y/plm"
    topics = ("plm", "single-file", "header-only")
    settings = "os", "arch", "compiler", "build_type"
    no_copy_source = True
    package_type = "header-library"
    exports_sources = "include/*", "test/*", "CMakeLists.txt"

    options = {
        "sanitizer": ["none", "asan", "tsan"],
    }
    default_options = {
        "sanitizer": "none",
    }

    def set_version(self):
        content = load(self, os.path.join(self.recipe_folder, "CMakeLists.txt"))
        match = re.search(
            r"\bproject\s*\([^)]*?\bVERSION\s+([0-9]+(?:\.[0-9]+){0,3})\b",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            raise ConanInvalidConfiguration(
                "Could not find project(... VERSION <version> ...) in CMakeLists.txt"
            )
        self.version = match.group(1)

    def layout(self):
        sanitizer = str(self.options.sanitizer)
        build_folder = "build" if sanitizer == "none" else f"build/{sanitizer}"
        cmake_layout(self, build_folder=build_folder)

    def generate(self):
        sanitizer = str(self.options.sanitizer)

        deps = CMakeDeps(self)
        deps.generate()

        tc = CMakeToolchain(self)
        tc.cache_variables["SANITIZER"] = sanitizer
        tc.presets_prefix = "conan" if sanitizer == "none" else f"conan-{sanitizer}"
        tc.generate()

    def build_requirements(self):
        self.test_requires("cmocka/1.1.8")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        cmake.ctest(cli_args=["--output-on-failure", "--no-tests=error"])

    def package(self):
        # This will also copy the "include" folder
        copy(self, "*.h", self.source_folder, self.package_folder)

    def package_info(self):
        # For header-only packages, libdirs and bindirs are not used
        # so it's recommended to set those as empty.
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
