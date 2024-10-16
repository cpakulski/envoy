#include "source/server/config_validation/admin.h"

namespace Envoy {
namespace Server {

// Pretend that handler was added successfully.
bool ValidationAdmin::addChunkedHandler(const std::string&, const std::string&, GenHandlerCb, bool,
                                        bool) {
  return true;
}
bool ValidationAdmin::addHandler(const std::string&, const std::string&, HandlerCb, bool, bool) {
  return true;
}

bool ValidationAdmin::removeHandler(const std::string&) { return true; }

const Network::Socket& ValidationAdmin::socket() { return *socket_; }

ConfigTracker& ValidationAdmin::getConfigTracker() { return config_tracker_; }

void ValidationAdmin::startHttpListener(const std::list<AccessLog::InstanceSharedPtr>&,
                                        const std::string&,
                                        Network::Address::InstanceConstSharedPtr,
                                        const Network::Socket::OptionsSharedPtr&,
                                        Stats::ScopePtr&&) {}

Http::Code ValidationAdmin::request(absl::string_view, absl::string_view, Http::ResponseHeaderMap&,
                                    std::string&) {
  PANIC("not implemented");
}

void ValidationAdmin::addListenerToHandler(Network::ConnectionHandler*) {}

} // namespace Server
} // namespace Envoy
