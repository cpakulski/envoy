#include "test/integration/http_integration.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PayloadValidator {
// namespace {

std::string filter_header_config = R"EOF(
name: envoy.filters.http.payload_validator
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.payload_validator.v3.PayloadValidator
  stat_prefix: test_p_v
  max_size: 25
)EOF";

std::string filter1_header_config = R"EOF(
)EOF";

std::string paths_header_config = R"EOF(
  paths:
)EOF";

std::string operations_header_config = R"EOF(
    operations:
)EOF";


std::string post_method_config = R"EOF(
    - method: POST  
      request_body:
        schema: |
          {
              "$schema": "http://json-schema.org/draft-07/schema#",
              "title": "A person",
              "properties": {
                  "foo": {
                      "type": "string",
                      "minLength": 10,
                      "maxLength": 10
                  }
              },
              "required": [
                  "foo"
              ],
              "type": "object"
          }
)EOF";

std::string delete_method_config = R"EOF(
    - method: DELETE
)EOF";


std::string put_method_config = R"EOF(
    - method: PUT
)EOF";

const std::string parameters_header = R"EOF(
      parameters: 
  )EOF";

const std::string query_required_param1 = R"EOF(
      - name: "param1"
        in: QUERY
        required: true
        schema: |
          {
            "type": "string"
          }
  )EOF";

const std::string query_required_param2 = R"EOF(
      - name: "param2"
        in: QUERY
        required: true
        schema: |
          {
            "type": "string"
          }
  )EOF";

const std::string query_non_required_param3 = R"EOF(
      - name: "param3"
        in: QUERY
        required: false
        schema: |
          {
            "type": "integer"
          }
  )EOF";

constexpr int methodName = 0;
 constexpr int    requestUrl = 1;
constexpr int     addBody = 2;
 constexpr int    body = 3;
 constexpr int    expectedCode = 4;

using TestVariables = std::tuple<std::string, std::string, bool, std::string, std::string>;
using IntegrationTestRequestParams = std::tuple<std::vector<std::string>, std::string, TestVariables>;
class PayloadValidatorIntegrationTest
    : public Envoy::HttpIntegrationTest,
      public ::testing::TestWithParam<IntegrationTestRequestParams> {
public:
  PayloadValidatorIntegrationTest()
      : HttpIntegrationTest(Http::CodecType::HTTP1, Network::Address::IpVersion::v4) {

#if 0
    std::string filter_config = R"EOF(
name: envoy.filters.http.payload_validator
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.payload_validator.v3.PayloadValidator
  stat_prefix: test_p_v
  max_size: 25
  paths:
  - path: "/test"
    operations:
    - method: POST  
      request_body:
        schema: |
          {
              "$schema": "http://json-schema.org/draft-07/schema#",
              "title": "A person",
              "properties": {
                  "foo": {
                      "type": "string",
                      "minLength": 10,
                      "maxLength": 10
                  }
              },
              "required": [
                  "foo"
              ],
              "type": "object"
          }
    - method: DELETE
    - method: PUT
)EOF";
#endif
        std::string filter_config = filter_header_config + paths_header_config; 
    filter_config += fmt::format(R"EOF(
  - path: {}
    )EOF", std::get<1>(GetParam()));
    for (const auto& config_part : std::get<0>(GetParam())) {
        filter_config += config_part;
    }
    config_helper_.prependFilter(filter_config);
    initialize();
  }
};

TEST_P(PayloadValidatorIntegrationTest, RejectedRequests) {
  const auto& test = std::get<2>(GetParam());
  codec_client_ = makeHttpConnection(lookupPort("http"));
  Http::TestRequestHeaderMapImpl request_headers{{":method", std::get<methodName>(test)},
                                                 {":path", std::get<requestUrl>(test)},
                                                 {":scheme", "http"},
                                                 {":authority", "host"}};

  IntegrationStreamDecoderPtr response;
  if (std::get<addBody>(test)) {
    // Send body.
    response = codec_client_->makeRequestWithBody(request_headers, std::get<body>(test));
  } else {
    response = codec_client_->makeHeaderOnlyRequest(request_headers);
  }

  // If expected reply code is 200, it means that test assumes that payload
  // was successfully validated and upstream server whould return 200.
  if (std::get<expectedCode>(test) == "200") {
    waitForNextUpstreamRequest();
    upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  }
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(response->complete());
  EXPECT_THAT(response->headers(), Http::HttpStatusIs(std::get<expectedCode>(test)));

  test_server_->waitForCounterEq("http.config_test.payload_validator.test_p_v.requests_validated",
                                 1);
  if (std::get<expectedCode>(test) != "200") {
    EXPECT_EQ(
        1, test_server_
               ->counter("http.config_test.payload_validator.test_p_v.requests_validation_failed")
               ->value());
    EXPECT_EQ(
        1,
        test_server_
            ->counter(
                "http.config_test.payload_validator.test_p_v.requests_validation_failed_enforced")
            ->value());
  }
}

// The following test cases test payload validation of requests.
// Test cases target different logical paths within the filter,
// not the payload validating library (one test case with wrong body
// is enough to determine that payload validator was reached).
INSTANTIATE_TEST_SUITE_P(
    PayloadValidatorIntegrationTestSuite, PayloadValidatorIntegrationTest,
    ::testing::Values(
        // POST without body.
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("POST", "/test", true, "{}", "422")),
                // POST with correct body.
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("POST", "/test", true, "{\"foo\":\"abcdefghij\"}", "200")),
                // POST with incorrect body.
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("POST", "/test", true, "{\"foo\": 1}", "422")),
                // POST with too large body. Body length is checked before passing it to validator.
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("POST", "/test", true, "{\"foo\":\"abcdefghijklmnop\"}", "413")),
                // DELETE is allowed but body is not validated. With or without body it should not be
                // stopped.
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("DELETE", "/test", true, "{\"foo\":\"klmnop\"}", "200")),
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("DELETE", "/test", false, "", "200")),
        // GET is not allowed.
        IntegrationTestRequestParams({operations_header_config, post_method_config, delete_method_config}, 
            "/test", 
                TestVariables("GET", "/test", false, "", "405")),

        // Test query parameters.
        IntegrationTestRequestParams({operations_header_config, post_method_config, parameters_header, query_required_param1}, 
            "/test", 
                TestVariables("POST", "/test?param1=test_string", true, "{\"foo\":\"abcdefghij\"}", "200")),
        IntegrationTestRequestParams({operations_header_config, post_method_config, parameters_header, query_required_param1}, 
            "/test", 
                TestVariables("POST", "/test?param2=test_string", true, "{\"foo\":\"abcdefghij\"}", "422")),
        IntegrationTestRequestParams({operations_header_config, post_method_config, parameters_header, query_required_param1}, 
            "/test", 
                TestVariables("POST", "/test", true, "{\"foo\":\"abcdefghij\"}", "422"))
    ));

// Validate responses.
class ResponseValidatorIntegrationTest
    : public Envoy::HttpIntegrationTest,
      public ::testing::TestWithParam<
          std::tuple<std::string, std::string, bool, std::string, std::string>> {
public:
  ResponseValidatorIntegrationTest()
      : HttpIntegrationTest(Http::CodecType::HTTP1, Network::Address::IpVersion::v4) {

    std::string filter_config = R"EOF(
name: envoy.filters.http.payload_validator
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.payload_validator.v3.PayloadValidator
  stat_prefix: test_p_v
  paths:
  - path: "/test"
    operations:
    - method: GET  
      responses:
      - http_status:
          code: 200
        response_body:
          schema: |
            {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "A person",
                "properties": {
                    "foo": {
                        "type": "string"
                    }
                },
                "required": [
                    "foo"
                ],
                "type": "object"
            }
    - method: DELETE
    - method: PUT
)EOF";
    config_helper_.prependFilter(filter_config);
    initialize();
  }
};

TEST_P(ResponseValidatorIntegrationTest, RejectedRequests) {
  const auto& param = GetParam();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", std::get<0>(param)},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {":authority", "host"}};

  IntegrationStreamDecoderPtr response;
  response = codec_client_->makeHeaderOnlyRequest(request_headers);

  waitForNextUpstreamRequest();

  if (std::get<2>(GetParam())) {
    upstream_request_->encodeHeaders(
        Http::TestResponseHeaderMapImpl{{":status", std::get<1>(param)}}, false);
    upstream_request_->encodeData(std::get<4>(param), true);
  } else {
    // Send only headers
    upstream_request_->encodeHeaders(
        Http::TestResponseHeaderMapImpl{{":status", std::get<1>(param)}}, true);
  }
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(response->complete());
  EXPECT_THAT(response->headers(), Http::HttpStatusIs(std::get<3>(param)));

  test_server_->waitForCounterEq("http.config_test.payload_validator.test_p_v.responses_validated",
                                 1);
  if (response->headers().getStatusValue() != "200") {
    EXPECT_EQ(
        1, test_server_
               ->counter("http.config_test.payload_validator.test_p_v.responses_validation_failed")
               ->value());
    EXPECT_EQ(
        1,
        test_server_
            ->counter(
                "http.config_test.payload_validator.test_p_v.responses_validation_failed_enforced")
            ->value());
  }
}

// The following test cases test payload validation of requests.
// Test cases target different logical paths within the filter,
// not the payload validating library (one test case with wrong body
// is enough to determine that payload validator was reached).
INSTANTIATE_TEST_SUITE_P(ResponseValidatorIntegrationTestSuite, ResponseValidatorIntegrationTest,
                         ::testing::Values(
                             // Response to GET without body.
                             std::make_tuple("GET", "200", false, "422", "{}"),
                             // Response to GET with incorrect body, but still in json format.
                             std::make_tuple("GET", "200", true, "422", "{\"foo\": 1}"),
                             // Response to GET with incorrect body.
                             std::make_tuple("GET", "200", true, "422", "blah}"),
                             // Response to GET with not allowed response code 202.
                             std::make_tuple("GET", "202", true, "422", ""),
                             // Response to GET with correct body.
                             std::make_tuple("GET", "200", true, "200",
                                             "{\"foo\":\"abcdefghij\"}")));

} // namespace PayloadValidator
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
