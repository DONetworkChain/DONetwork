#Redefine the __FILE__ macro for the source file of the current target
function(redefine_file_macro targetname)
    #Get all source files of the current target
    get_target_property(source_files "${targetname}" SOURCES)
    #Traverse source files
    foreach(sourcefile ${source_files})
        #Get the compilation parameters of the current source file
        get_property(defs SOURCE "${sourcefile}"
            PROPERTY COMPILE_DEFINITIONS)
        #Get the absolute path of the current file
        get_filename_component(filepath "${sourcefile}" ABSOLUTE)
        #Replace the project path in the absolute path with an empty one, and get the relative path of the source file to the project path
        string(REPLACE ${PROJECT_SOURCE_DIR}/ "" relpath ${filepath})
        #Add the compilation parameter we want to add (__FILE__ definition) to the original compilation parameter
        list(APPEND defs "__FILE__=\"${relpath}\"")
        #Resetting the compilation parameters of the source file
        set_property(
            SOURCE "${sourcefile}"
            PROPERTY COMPILE_DEFINITIONS ${defs}
            )
    endforeach()
endfunction()
