#include <iostream>
#include <string>
#include <VigenereCTF.pb.h>
#include <VigenereCTF.grpc.pb.h>

#include <grpc/grpc.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

class PasswordExportService final : public PasswordExport::Service
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
    PasswordExportService(const std::string& secret_key, const std::string& flag);
    virtual ::grpc::Status getEncryptedPassword(::grpc::ServerContext* context, const ::Empty* request, ::Password* response) override;
    virtual ::grpc::Status hint1(::grpc::ServerContext* context, const ::Empty* request, ::HintResponse* response) override;
    virtual ::grpc::Status hint2(::grpc::ServerContext* context, const ::Empty* request, ::HintResponse* response) override;
    virtual ::grpc::Status hint3(::grpc::ServerContext* context, const ::Empty* request, ::HintResponse* response) override;
};

int main(int argc, char** argv)
{
    grpc::ServerBuilder builder;
    builder.AddListeningPort(std::string(argv[1])+":"+std::string(argv[2]), grpc::InsecureServerCredentials());

    PasswordExportService my_service{argv[3], argv[4]};
    builder.RegisterService(&my_service);
    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    server->Wait();
}

PasswordExportService::PasswordExportService(const std::string &secret_key, const std::string &flag)
    :m_secret_key{secret_key}, m_flag{flag}
{
}

grpc::Status PasswordExportService::getEncryptedPassword(::grpc::ServerContext* context, const ::Empty* request, ::Password* response)
{
    response->set_password(encryption(m_flag));
    return grpc::Status();
}

grpc::Status PasswordExportService::hint1(::grpc::ServerContext *context, const ::Empty *request, ::HintResponse *response)
{
    response->set_hint("The Vigenere cipher is a polyalphabetic encryption algorithm invented by the French cryptologist Blaise de Vigenere in the 16th century");
    return grpc::Status();
}

grpc::Status PasswordExportService::hint2(::grpc::ServerContext *context, const ::Empty *request, ::HintResponse *response)
{
    response->set_hint("Vigenere hates Kasiski");
    return grpc::Status();
}

grpc::Status PasswordExportService::hint3(::grpc::ServerContext *context, const ::Empty *request, ::HintResponse *response)
{
    response->set_hint("English. Alphabet. How were the 'FLAG's in previous challanges?");
    return grpc::Status();
}
