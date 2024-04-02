file(GLOB LIB_FILES "~/mvfst/_build/mvfst/lib/lib*.a")

add_custom_command(OUTPUT libmvfst.a
                   COMMAND ../combine_libs.sh
                   DEPENDS ${LIB_FILES})

add_custom_target(CombineLibs ALL DEPENDS libmvfst.a)
