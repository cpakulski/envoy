#include "contrib/payload_validator/filters/http/source/filter.h"

#include <chrono>
#include <cstdint>
#include <nlohmann/json-schema.hpp>
#include <string>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/http/codes.h"
#include "source/common/http/exception.h"
#include "source/common/http/utility.h"

#include "absl/container/fixed_array.h"
#include "fmt/format.h"

using nlohmann::json;
using nlohmann::json_schema::json_validator;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PayloadValidator {

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool stream_end) {
  config_.stats()->requests_validated_.inc();

 auto request_path = headers.getPathValue();
 ENVOY_LOG(debug, "Validating headers. Path {}", request_path);

    request_path.remove_prefix(1);
  auto param_start = request_path.find('?');
  if (param_start != absl::string_view::npos) {
        request_path.remove_suffix(request_path.length() - param_start);
    }
    // Break the path into segments separeted by forward slash.
    std::vector<absl::string_view> segments = absl::StrSplit(request_path, '/');

  // Find the path matching received request.
  std::vector<Path>::iterator matched_path;
  for (matched_path = config_.paths_.begin(); matched_path != config_.paths_.end(); matched_path++) {
    if (segments.size() != (*matched_path).path_template_.fixed_segments_.size() + (*matched_path).path_template_.templated_segments_.size()) {
        // different number of forward slashes in the path.
        continue;
    }
    
    ENVOY_LOG(debug, "Matching against path template {}", (*matched_path).path_template_.full_path_);
    const auto path_match_result = checkPath((*matched_path).path_template_, segments); 
    switch (path_match_result.first) {
        case  PathValidationResult::MATCHED:
            ENVOY_LOG(debug, "Path matches template. Path validation successful");
            break;
        case PathValidationResult::NOT_MATCHED:
            ENVOY_LOG(debug, "Path does not match template");
        // Try another template.
        continue;
        case PathValidationResult::MATCHED_WITH_ERRORS:
            std::string error_message = 
        fmt::format("Validation of path syntax failed: {}", path_match_result.second.value());
            ENVOY_LOG(info, "Path matches template. {}", error_message);
    local_reply_ = true;
    decoder_callbacks_->sendLocalReply(
        Http::Code::UnprocessableEntity,
        error_message,
        nullptr, absl::nullopt, "");
    config_.stats()->requests_validation_failed_.inc();
    config_.stats()->requests_validation_failed_enforced_.inc();
    return Http::FilterHeadersStatus::StopIteration;
        break;
    }
    // Break the for loop.
    break;
  }

  if (matched_path == config_.paths_.end()) {
    // None of the paths matched.
    local_reply_ = true;
    decoder_callbacks_->sendLocalReply(
        Http::Code::Forbidden,
        fmt::format("Path is not allowed"),
        nullptr, absl::nullopt, "");
        ENVOY_LOG(info, "Request validation failed: path {} is not allowed", request_path);
    config_.stats()->requests_validation_failed_.inc();
    config_.stats()->requests_validation_failed_enforced_.inc();
    return Http::FilterHeadersStatus::StopIteration;
    }

  // get method header
  const absl::string_view method = headers.getMethodValue();
  const auto& it = (*matched_path).operations_.find(method);
  local_reply_ = false;

  ENVOY_LOG(debug, "Method is {} request", method);

  if (it == (*matched_path).operations_.end()) {
    // Return method not allowed.
    local_reply_ = true;
    std::string error_msg = fmt::format("Method {} is not allowed for path {}", method, request_path);
    decoder_callbacks_->sendLocalReply(Http::Code::MethodNotAllowed, error_msg, nullptr, absl::nullopt,
                                       "");
    ENVOY_LOG(info, "Request validation failed: {}", error_msg);
    config_.stats()->requests_validation_failed_.inc();
    config_.stats()->requests_validation_failed_enforced_.inc();
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Store the pointer to the description of request and response associated with the received
  // method.
  current_operation_ = (*it).second;

  const auto result = validateParams(current_operation_->params_, headers.getPathValue());
  if (!result.first) {
    local_reply_ = true;
    std::string error_msg = fmt::format("Query parameters are not as expected: {}", result.second.value());
    decoder_callbacks_->sendLocalReply(Http::Code::UnprocessableEntity, error_msg,
                                       nullptr, absl::nullopt, "");
    ENVOY_LOG(info, "Request validation failed: {}", error_msg);
    config_.stats()->requests_validation_failed_.inc();
    config_.stats()->requests_validation_failed_enforced_.inc();
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (stream_end) {
    if (current_operation_->request_->active()) {
      local_reply_ = true;
      decoder_callbacks_->sendLocalReply(Http::Code::UnprocessableEntity, "Payload body is missing",
                                         nullptr, absl::nullopt, "");
      ENVOY_LOG(info, "Request validation failed: {}", "Payload body is missing");
      config_.stats()->requests_validation_failed_.inc();
      config_.stats()->requests_validation_failed_enforced_.inc();
      return Http::FilterHeadersStatus::StopIteration;
    };
    return Http::FilterHeadersStatus::Continue;
  }

  ENVOY_LOG(debug, "Path and query parameters validation succeeded");
  // Do not send headers upstream yet, because the body validation may fail.
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& data, bool stream_end) {
  // If there is a request validator for this method, entire data must be buffered
  // in order to do validation.
  // If there is no validator, there is no need for buffering.
  auto& req_validator = current_operation_->request_;
  if (req_validator == nullptr) {
    return Http::FilterDataStatus::Continue;
  }

  const auto* buffer = decoder_callbacks_->decodingBuffer();

  uint32_t total_length = data.length();
  if (buffer != nullptr) {
    total_length += buffer->length();
  }

  if (total_length > config_.maxSize()) {
    local_reply_ = true;
    std::string error_msg = fmt::format("Request payload exceed {} bytes", config_.maxSize());
    decoder_callbacks_->sendLocalReply(
        Http::Code::PayloadTooLarge,
        error_msg,
        nullptr, absl::nullopt, "");
    ENVOY_LOG(info, "Request validation failed: {}", error_msg);
    config_.stats()->requests_validation_failed_.inc();
    config_.stats()->requests_validation_failed_enforced_.inc();
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  if (!stream_end) {
    decoder_callbacks_->addDecodedData(data, false);
    return Http::FilterDataStatus::StopIterationAndBuffer;
  }

  if (!req_validator->active()) {
    // There is no body validator attached to the request.
    // The body is buffered only to check the max size.
    ENVOY_LOG(trace, "Request body is not validated because there was no schema in config.");
    return Http::FilterDataStatus::Continue;
  }

  if (buffer == nullptr) {
    buffer = &data;
  } else {
    // Add the last chunk to decode buffer.
    decoder_callbacks_->addDecodedData(data, false);
  }

  std::string body_to_validate;
  body_to_validate.assign(std::string(
      static_cast<char*>((const_cast<Buffer::Instance&>(*buffer)).linearize(buffer->length())),
      buffer->length()));
  if (buffer->length() != 0) {
    auto result = req_validator->validate(body_to_validate);

    if (!result.first) {
      local_reply_ = true;
      std::string error_msg = fmt::format("Body does not match schema: {}", result.second.value());
      decoder_callbacks_->sendLocalReply(Http::Code::UnprocessableEntity,
                                         error_msg,
                                         nullptr, absl::nullopt, "");
    ENVOY_LOG(info, "Request validation failed: {}", error_msg);
      config_.stats()->requests_validation_failed_.inc();
      config_.stats()->requests_validation_failed_enforced_.inc();
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
  }

  ENVOY_LOG(debug, "Request body validation succeeded");

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {

  return Http::FilterTrailersStatus::Continue;
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool stream_end) {
  if (local_reply_) {
    return Http::FilterHeadersStatus::Continue;
  }

  // get Status header
  absl::optional<uint64_t> status = Http::Utility::getResponseStatusOrNullopt(headers);

  if (status == absl::nullopt) {
    local_reply_ = true;
    encoder_callbacks_->sendLocalReply(Http::Code::UnprocessableEntity,
                                       "Incorrect response. Status header is missing.", nullptr,
                                       absl::nullopt, "");
    config_.stats()->responses_validated_.inc();
    config_.stats()->responses_validation_failed_.inc();
    config_.stats()->responses_validation_failed_enforced_.inc();
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (current_operation_->responses_.empty()) {
    return Http::FilterHeadersStatus::Continue;
  }

  config_.stats()->responses_validated_.inc();
  const auto& it = current_operation_->responses_.find(status.value());

  if (it == current_operation_->responses_.end()) {
    local_reply_ = true;
    // Return code not allowed.
    config_.stats()->responses_validation_failed_.inc();
    config_.stats()->responses_validation_failed_enforced_.inc();
    std::string error_msg = fmt::format("Not allowed response status code: {}", status.value());
    encoder_callbacks_->sendLocalReply(
        Http::Code::UnprocessableEntity,
        error_msg, nullptr, absl::nullopt,
        "");
    ENVOY_LOG(info, "Response validation failed: {}", error_msg);
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (stream_end) {
    if ((*it).second != nullptr) {
      // Body is not present but is required.
      local_reply_ = true;
      config_.stats()->responses_validation_failed_.inc();
      config_.stats()->responses_validation_failed_enforced_.inc();
      std::string error_msg = "Response body is missing";
      encoder_callbacks_->sendLocalReply(Http::Code::UnprocessableEntity,
                                         error_msg, nullptr, absl::nullopt, "");
    ENVOY_LOG(info, "Response validation failed: {}", error_msg);
      return Http::FilterHeadersStatus::StopIteration;
    } else {
      return Http::FilterHeadersStatus::Continue;
    }
  }

  // Store reference to response validator.
  response_validator_ = (*it).second;

  // Do not continue yet, as body validation may fail.
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus Filter::encodeData(Buffer::Instance& data, bool stream_end) {
  if (local_reply_) {
    // Do not validate locally generated response.
    return Http::FilterDataStatus::Continue;
  }

  if (response_validator_ == nullptr) {
    return Http::FilterDataStatus::Continue;
  }

  const auto* buffer = encoder_callbacks_->encodingBuffer();

  if (!stream_end) {
    encoder_callbacks_->addEncodedData(data, false);
    return Http::FilterDataStatus::StopIterationAndBuffer;
  }

  if (buffer == nullptr) {
    buffer = &data;
  } else {
    encoder_callbacks_->addEncodedData(data, false);
  }

  std::string body_to_validate;
  body_to_validate.assign(std::string(
      static_cast<char*>((const_cast<Buffer::Instance&>(*buffer)).linearize(buffer->length())),
      buffer->length()));

  if (buffer->length() != 0) {
    auto result = response_validator_->validate(body_to_validate);

    if (!result.first) {
      local_reply_ = true;
      config_.stats()->responses_validation_failed_.inc();
      config_.stats()->responses_validation_failed_enforced_.inc();
      std::string error_msg = fmt::format("Response body does not match schema: {}", result.second.value());
      encoder_callbacks_->sendLocalReply(Http::Code::UnprocessableEntity,
                                         error_msg,
                                         nullptr, absl::nullopt, "");
    ENVOY_LOG(info, "Response validation failed: {}", error_msg);
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
  }


  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Filter::encodeTrailers(Http::ResponseTrailerMap&) {
  return Http::FilterTrailersStatus::Continue;
}

} // namespace PayloadValidator
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
