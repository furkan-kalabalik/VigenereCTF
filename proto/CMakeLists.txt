find_package(protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(Threads)

#
# Protobuf/Grpc source files
#
set(PROTO_FILES VigenereCTF.proto)

#
# Add Library target with protobuf sources
#
add_library(libvigenere_proto ${PROTO_FILES})
target_link_libraries(libvigenere_proto
    PUBLIC
        gRPC::grpc
        gRPC::grpc++
        gRPC::grpc++_reflection
        protobuf::libprotobuf
)
target_include_directories(libvigenere_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

#
# Compile protobuf and grpc files in myproto target to cpp
#
get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)
protobuf_generate(TARGET libvigenere_proto LANGUAGE cpp)
protobuf_generate(TARGET libvigenere_proto LANGUAGE grpc GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc PLUGIN "protoc-gen-grpc=${grpc_cpp_plugin_location}")