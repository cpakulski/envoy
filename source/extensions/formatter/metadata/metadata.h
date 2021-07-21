#pragma once

#include <string>

#include "envoy/config/typed_config.h"
#include "envoy/registry/registry.h"

#include "source/common/formatter/substitution_formatter.h"

namespace Envoy {
namespace Extensions {
namespace Formatter {

// Access log handler for METADATA( command.
class MetadataFormatterCommandParser : public ::Envoy::Formatter::CommandParser {
public:
  MetadataFormatterCommandParser();
  ::Envoy::Formatter::FormatterProviderPtr parse(const std::string& token, size_t,
                                                 size_t) const override;

private:
  static const size_t MetadataFormatterParamStart{sizeof("METADATA(") - 1};

  // Map used to dispatch types of metadata to individual handlers which will
  // access required metadata object.
  std::map<std::string,
           std::function<::Envoy::Formatter::FormatterProviderPtr(
               const std::string& filter_namespace, const std::vector<std::string>& path,
               absl::optional<size_t> max_length)>>
      metadata_formatter_providers_;
};

} // namespace Formatter
} // namespace Extensions
} // namespace Envoy
