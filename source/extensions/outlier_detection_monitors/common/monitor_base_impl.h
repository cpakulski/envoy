#pragma once

#include "envoy/config/typed_config.h"
#include "envoy/extensions/outlier_detection_monitors/common/v3/error_types.pb.h"
#include "envoy/extensions/outlier_detection_monitors/common/v3/error_types.pb.validate.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/upstream/outlier_detection.h"

#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace Outlier {

using namespace Envoy::Upstream::Outlier;

// ErrorsBucket is used by outlier detection monitors and is used to
// "catch" reported Error (TypedError);
class ErrorsBucket {
public:
  virtual bool matchType(const ExtResult&) const PURE;
  virtual bool match(const ExtResult&) const PURE;
  virtual ~ErrorsBucket() {}
};

template <class E> class TypedErrorsBucket : public ErrorsBucket {
public:
  bool matchType(const ExtResult& result) const override {
    return absl::holds_alternative<E>(result);
  }

  virtual ~TypedErrorsBucket() {}
};

using ErrorsBucketPtr = std::unique_ptr<ErrorsBucket>;

// Class defines a range of consecutive HTTP codes.
class HTTPCodesBucket : public TypedErrorsBucket<Upstream::Outlier::HttpCode> {
public:
  HTTPCodesBucket() = delete;
  HTTPCodesBucket(uint64_t start, uint64_t end) : start_(start), end_(end) {}
  bool match(const ExtResult&) const override;

  virtual ~HTTPCodesBucket() {}

private:
  uint64_t start_, end_;
};

// Class defines a "bucket" which catches LocalOriginEvent.
class LocalOriginEventsBucket : public TypedErrorsBucket<Upstream::Outlier::LocalOriginEvent> {
public:
  LocalOriginEventsBucket() = default;
  bool match(const ExtResult&) const override;
};

class ExtMonitorBase : public ExtMonitor {
public:
  ExtMonitorBase(const std::string& name, uint32_t enforce) : name_(name), enforce_(enforce) {}
  ExtMonitorBase() = delete;
  virtual ~ExtMonitorBase() {}
  void putResult(const ExtResult&) override;

  void setExtMonitorCallback(ExtMonitorCallback callback) override { callback_ = callback; }

  void reset() override { onReset(); }
  std::string name() const { return name_; }

  void processBucketsConfig(
      const envoy::extensions::outlier_detection_monitors::common::v3::ErrorBuckets& config);
  void addErrorBucket(ErrorsBucketPtr&& bucket) { buckets_.push_back(std::move(bucket)); }

protected:
  virtual bool onError() PURE;
  virtual void onSuccess() PURE;
  virtual void onReset() PURE;
  virtual std::string getFailedExtraInfo() { return ""; }

  std::string name_;
  uint32_t enforce_{100};
  ExtMonitor::ExtMonitorCallback callback_;
  std::vector<ErrorsBucketPtr> buckets_;
};

template <class ConfigProto>
class ExtMonitorFactoryBase : public Upstream::Outlier::ExtMonitorFactory {
public:
  ExtMonitorCreateFn createMonitor(const std::string& monitor_name, const Protobuf::Message& config,
                                   ExtMonitorFactoryContext& context) override {
    // This should throw exception if config is wrong.
    return createMonitorFromProtoTyped(monitor_name,
                                       Envoy::MessageUtil::downcastAndValidate<const ConfigProto&>(
                                           config, context.messageValidationVisitor()),
                                       context);
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<ConfigProto>();
  }

  std::string name() const override { return name_; }

  ExtMonitorFactoryBase(const std::string& name) : name_(name) {}

private:
  virtual ExtMonitorCreateFn createMonitorFromProtoTyped(const std::string& monitor_name,
                                                         const ConfigProto& config,
                                                         ExtMonitorFactoryContext& context) PURE;

  const std::string name_;
};

} // namespace Outlier
} // namespace Extensions
} // namespace Envoy
