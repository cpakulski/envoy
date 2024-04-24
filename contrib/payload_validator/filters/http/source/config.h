#pragma once

#include <string>

#include "envoy/server/filter_config.h"

#include "source/extensions/filters/http/common/factory_base.h"

#include "contrib/envoy/extensions/filters/http/payload_validator/v3/payload_validator.pb.h"
#include "contrib/envoy/extensions/filters/http/payload_validator/v3/payload_validator.pb.validate.h"

#include <nlohmann/json-schema.hpp>

using nlohmann::json_schema::json_validator;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PayloadValidator {

/**
 * Config registration for http payload validator filter.
 */
class FilterConfig
    : public Common::FactoryBase<
          envoy::extensions::filters::http::payload_validator::v3::PayloadValidator> {
public:
  FilterConfig() : FactoryBase("envoy.filters.http.payload_validator") {}
  json_validator& getValidator() { return validator_; }

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::payload_validator::v3::PayloadValidator& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;

  json_validator validator_;
};

} // namespace PayloadValidator
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
