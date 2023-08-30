#include <iostream>
#include <string>
#include <VigenereCTF.pb.h>
#include <VigenereCTF.grpc.pb.h>

#include <grpc/grpc.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

class VigenereCTFService final : public VigenereCTF::Service
{
private:
    std::string m_secret_key;
    std::string m_flag;
    std::string encryption(const std::string& t)
    {
        std::string output;
        for (int i = 0, j = 0; i < t.length(); ++i)
        {
            char c = t[i];
            if (c >= 'a' && c <= 'z')
                c += 'A' - 'a';
            else if (c < 'A' || c > 'Z')
                continue;
            output += (c + m_secret_key[j] - 2 * 'A') % 26 + 'A';
            j = (j + 1) % m_secret_key.length();
        }
        return output;
    }
    std::string decryption(const std::string& t)
    {
        std::string output;
        for (int i = 0, j = 0; i < t.length(); ++i)
        {
            char c = t[i];
            if (c >= 'a' && c <= 'z')
                c += 'A' - 'a';
            else if (c < 'A' || c > 'Z')
                continue;
            output += (c - m_secret_key[j] + 26) % 26 + 'A';
            j = (j + 1) % m_secret_key.length();
        }
        return output;
    }

public:
    VigenereCTFService(const std::string& secret_key, const std::string& flag);
    grpc::Status getFlag(::grpc::ServerContext* context, const ::Empty* request, ::FlagResponse* response) override;
    grpc::Status encode(::grpc::ServerContext* context, const ::EncodeRequest* request, ::EncodeResponse* response) override;
    grpc::Status hint(::grpc::ServerContext* context, const ::Empty* request, ::HintResponse* response) override;
};

int main(int argc, char** argv)
{
    grpc::ServerBuilder builder;
    builder.AddListeningPort(std::string(argv[1])+":"+std::string(argv[2]), grpc::InsecureServerCredentials());

    VigenereCTFService my_service{argv[3], argv[4]};
    builder.RegisterService(&my_service);
    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    server->Wait();
}

VigenereCTFService::VigenereCTFService(const std::string &secret_key, const std::string &flag)
    :m_secret_key{secret_key}, m_flag{flag}
{
}

grpc::Status VigenereCTFService::getFlag(::grpc::ServerContext *context, const ::Empty *request, ::FlagResponse *response)
{
    response->set_flag(encryption(m_flag));
    return grpc::Status();
}

grpc::Status VigenereCTFService::encode(::grpc::ServerContext *context, const ::EncodeRequest *request, ::EncodeResponse *response)
{
    response->set_encoded_output(encryption(request->input()));
    return grpc::Status();
}

grpc::Status VigenereCTFService::hint(::grpc::ServerContext *context, const ::Empty *request, ::HintResponse *response)
{
    response->set_hint("Looking for a substitution");
    return grpc::Status();
}
