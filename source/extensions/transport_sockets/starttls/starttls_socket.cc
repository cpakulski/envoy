#include "extensions/transport_sockets/starttls/starttls_socket.h"

#include <iostream>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace StartTls {

using absl::ascii_isdigit;

Network::IoResult StartTlsSocket::doRead(Buffer::Instance& buffer) {
  ENVOY_LOG(trace, "starttls: doRead ({}) {}", buffer.length(), buffer.toString());
  Network::IoResult result;

  if (passthrough_) {
    return passthrough_->doRead(buffer);
  }

  Envoy::Buffer::OwnedImpl local_buffer;
  result = raw_socket_->doRead(local_buffer);
  buffer.add(local_buffer);

  ENVOY_LOG(debug, "starttls: local_buffer {}", local_buffer.toString());

  // absl::StrAppend(&command_buffer_, local_buffer.toString());

  uint32_t code = buffer.peekBEInt<uint32_t>(4);
  // Startup message with 1234 in the most significant 16 bits
  // indicate request to encrypt (SSLRequest).
  if (code == 0x4D2162F) {
    ENVOY_LOG(debug, "starttls: SSL request sent");

    Envoy::Buffer::OwnedImpl outbuf;
    outbuf.add("S");
    raw_socket_->doWrite(outbuf, false);
    buffer.drain(buffer.length());
    ssl_socket_->setTransportSocketCallbacks(*callbacks_);
    ssl_socket_->onConnected();

    passthrough_ = std::move(ssl_socket_);
    raw_socket_.reset();
  } else {
    // go to passthrough mode
    ENVOY_LOG(trace, "starttls: passthrough default to raw_socket");
    passthrough_ = std::move(raw_socket_);
    ssl_socket_.reset();
  }

  return result;
}

Network::IoResult StartTlsSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  ENVOY_LOG(trace, "starttls: doWrite ({}) {}", buffer.length(), buffer.toString());

  if (passthrough_) {
    return passthrough_->doWrite(buffer, end_stream);
  }

  Envoy::Buffer::OwnedImpl local;
  local.move(buffer);

  Network::IoResult result = raw_socket_->doWrite(local, end_stream);
  result.bytes_processed_ = local.length();
  return result;
}

// TODO: right now this just expects DownstreamTlsContext in
// TransportSocket.typed_config which it passes to both transport sockets. There
// probably needs to be a separate config proto for this that can hold the
// config protos for both RawBuffer/SslSocket.
Network::TransportSocketPtr ServerStartTlsSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsSharedPtr transport_socket_options) const {
  ENVOY_LOG(trace, "starttls: createTransportSocket");
  return std::make_unique<StartTlsSocket>(
      raw_socket_factory_->createTransportSocket(transport_socket_options),
      tls_socket_factory_->createTransportSocket(transport_socket_options),
      transport_socket_options);
}

ServerStartTlsSocketFactory::~ServerStartTlsSocketFactory() {}

} // namespace StartTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
